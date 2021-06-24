/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/linkage.h>
#include <asm/sev-ap-jumptable.h>

/*
 * This file contains the source code for the binary blob which gets copied to
 * the SEV-ES AP Jumptable to park APs while offlining CPUs or booting a new
 * kernel via KEXEC.
 *
 * The AP Jumptable is the only safe place to put this code, as any memory the
 * kernel allocates will be owned (and possibly overwritten) by the new kernel
 * once the APs are woken up.
 *
 * This code runs in 16-bit protected mode, the CS, DS, and SS segment bases are
 * set to the beginning of the AP Jumptable page.
 *
 * Since the GDT will also be gone when the AP wakes up, this blob contains its
 * own GDT, which is set up by the AP Jumptable setup code with the correct
 * offsets.
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

	.text
	.org 0x0
	.code16
SYM_DATA_START(ap_jumptable_header)
	.word	0			/* reset IP */
	.word	0			/* reset CS */
	.word	ap_jumptable_gdt	/* GDT Offset   */
SYM_DATA_END(ap_jumptable_header)

	.org	SEV_APJT_ENTRY
SYM_CODE_START(ap_park_asm)

	/* Switch to AP Jumptable GDT first */
	lgdtl	ap_jumptable_gdt

	/* Reload CS */
	ljmpw	$SEV_APJT_CS16, $1f
1:

	/* Reload DS and SS */
	movl	$SEV_APJT_DS16, %ecx
	movl	%ecx, %ds
	movl	%ecx, %ss

	/*
	 * Setup a stack pointing to the end of the AP Jumptable page.
	 * The stack is needed ot reset EFLAGS after wakeup.
	 */
	movl	$0x1000, %esp

	/* Execute AP reset hold VMGEXIT */
2:	xorl	%edx, %edx
	movl	$0x6, %eax
	movl	$0xc0010130, %ecx
	wrmsr
	rep; vmmcall
	rdmsr
	movl	%eax, %ecx
	andl	$0xfff, %ecx
	cmpl	$0x7, %ecx
	jne	2b
	shrl	$12, %eax
	jnz	3f
	testl	%edx, %edx
	jnz	3f
	jmp	2b
3:
	/*
	 * Successfully woken up - Patch the correct target into the far jump at
	 * the end. An indirect far jump does not work here, because at the time
	 * the jump is executed DS is already loaded with real-mode values.
	 */

	/* Jump target is at address 0x0 - copy it to the far jump instruction */
	movl	$0, %ecx
	movl	(%ecx), %eax
	movl	%eax, jump_target

	/* Reset EFLAGS */
	pushl	$2
	popfl

	/* Setup DS and SS for real-mode */
	movl	$0x18, %ecx
	movl	%ecx, %ds
	movl	%ecx, %ss

	/* Reset remaining registers */
	movl	$0, %esp
	movl	$0, %eax
	movl	$0, %ebx
	movl	$0, %edx

	/* Reset CR0 to get out of protected mode */
	movl	$0x60000010, %ecx
	movl	%ecx, %cr0

	/*
	 * The below sums up to a far-jump instruction which jumps to the reset
	 * vector configured in the AP Jumptable and to real-mode. An indirect
	 * jump would be cleaner, but requires a working DS base/limit. DS is
	 * already loaded with real-mode values, therefore a direct far jump is
	 * used which got the correct target patched in.
	 */
	.byte	0xea
SYM_DATA_LOCAL(jump_target, .long 0)

SYM_CODE_END(ap_park_asm)
	/* Here comes the GDT */
	.balign	16
SYM_DATA_START_LOCAL(ap_jumptable_gdt)
	/* Offset zero used for GDT descriptor */
	.word	ap_jumptable_gdt_end - ap_jumptable_gdt - 1
	.long	ap_jumptable_gdt
	.word	0

	/* 16 bit code segment - setup at boot */
	.quad 0

	/* 16 bit data segment - setup at boot */
	.quad 0

	/* Offset 0x8 - real-mode data segment */
	.long	0xffff0180
	.long	0x00009300
SYM_DATA_END_LABEL(ap_jumptable_gdt, SYM_L_LOCAL, ap_jumptable_gdt_end)

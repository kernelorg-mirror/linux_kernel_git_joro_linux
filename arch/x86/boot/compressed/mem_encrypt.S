/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2017 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 */

#include <linux/linkage.h>

#include <asm/processor-flags.h>
#include <asm/msr.h>
#include <asm/asm-offsets.h>
#include <asm/segment.h>

	.text
	.code32
SYM_FUNC_START(get_sev_encryption_bit)
	xor	%eax, %eax

#ifdef CONFIG_AMD_MEM_ENCRYPT
	push	%ebx
	push	%ecx
	push	%edx

	/* Check if running under a hypervisor */
	movl	$1, %eax
	cpuid
	bt	$31, %ecx		/* Check the hypervisor bit */
	jnc	.Lno_sev

	movl	$0x80000000, %eax	/* CPUID to check the highest leaf */
	cpuid
	cmpl	$0x8000001f, %eax	/* See if 0x8000001f is available */
	jb	.Lno_sev

	/*
	 * Check for the SEV feature:
	 *   CPUID Fn8000_001F[EAX] - Bit 1
	 *   CPUID Fn8000_001F[EBX] - Bits 5:0
	 *     Pagetable bit position used to indicate encryption
	 */
	movl	$0x8000001f, %eax
	cpuid
	bt	$1, %eax		/* Check if SEV is available */
	jnc	.Lno_sev

	movl	$MSR_AMD64_SEV, %ecx	/* Read the SEV MSR */
	rdmsr
	bt	$MSR_AMD64_SEV_ENABLED_BIT, %eax	/* Check if SEV is active */
	jnc	.Lno_sev

	movl	%ebx, %eax
	andl	$0x3f, %eax		/* Return the encryption bit location */
	jmp	.Lsev_exit

.Lno_sev:
	xor	%eax, %eax

.Lsev_exit:
	pop	%edx
	pop	%ecx
	pop	%ebx

#endif	/* CONFIG_AMD_MEM_ENCRYPT */

	ret
SYM_FUNC_END(get_sev_encryption_bit)

#ifdef CONFIG_AMD_MEM_ENCRYPT
/*
 * Write an IDT entry into boot32_idt
 *
 * Parameters:
 *
 * %eax:	Handler address
 * %edx:	Vector number
 *
 * Physical offset is expected in %ebp
 */
SYM_FUNC_START(startup32_set_idt_entry)
	push    %ebx
	push    %ecx

	/* IDT entry address to %ebx */
	leal    boot32_idt(%ebp), %ebx
	shl	$3, %edx
	addl    %edx, %ebx

	/* Build IDT entry, lower 4 bytes */
	movl    %eax, %edx
	andl    $0x0000ffff, %edx
	movl    $__KERNEL32_CS, %ecx
	shl     $16, %ecx
	orl     %ecx, %edx

	/* Store lower 4 bytes to IDT */
	movl    %edx, (%ebx)

	/* Build IDT entry, upper 4 bytes */
	movl    %eax, %edx
	andl    $0xffff0000, %edx
	orl     $0x00008e00, %edx

	/* Store upper 4 bytes to IDT */
	movl    %edx, 4(%ebx)

	pop     %ecx
	pop     %ebx
	ret
SYM_FUNC_END(startup32_set_idt_entry)

SYM_FUNC_START(startup32_load_idt)
	/* Load IDT */
	addl    %ebp, boot32_idt_desc+2(%ebp)
	lidt    boot32_idt_desc(%ebp)

	ret
SYM_FUNC_END(startup32_load_idt)
#endif

	.code64
SYM_FUNC_START(set_sev_encryption_mask)
#ifdef CONFIG_AMD_MEM_ENCRYPT
	push	%rbp
	push	%rdx

	movq	%rsp, %rbp		/* Save current stack pointer */

	call	get_sev_encryption_bit	/* Get the encryption bit position */
	testl	%eax, %eax
	jz	.Lno_sev_mask

	bts	%rax, sme_me_mask(%rip)	/* Create the encryption mask */

.Lno_sev_mask:
	movq	%rbp, %rsp		/* Restore original stack pointer */

	pop	%rdx
	pop	%rbp
#endif

	xor	%rax, %rax
	ret
SYM_FUNC_END(set_sev_encryption_mask)

	.data

#ifdef CONFIG_AMD_MEM_ENCRYPT
	.balign	8
SYM_DATA(sme_me_mask, .quad 0)

SYM_DATA_START(boot32_idt_desc)
	.word   boot32_idt_end - boot32_idt - 1
	.long   boot32_idt
SYM_DATA_END(boot32_idt_desc)
	.balign 8
SYM_DATA_START(boot32_idt)
	.rept 32
	.quad 0
	.endr
SYM_DATA_END_LABEL(boot32_idt, SYM_L_GLOBAL, boot32_idt_end)

#endif

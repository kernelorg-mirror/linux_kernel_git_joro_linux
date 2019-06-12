/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2017 Advanced Micro Devices, Inc.
 *
 * Author: Tom Lendacky <thomas.lendacky@amd.com>
 *         Joerg Roedel <jroedel@suse.de>
 */

#include <linux/linkage.h>

#include <asm/processor-flags.h>
#include <asm/msr.h>
#include <asm/asm-offsets.h>
#include <asm/segment.h>
#include "boot_idt.h"

	.text
	.code32
ENTRY(get_sev_encryption_bit)
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
ENDPROC(get_sev_encryption_bit)

ENTRY(boot32_install_vc_handler)
	BOOT_IDT_ENTRY BOOT_VECTOR_VC boot32_vc_handler
	ret
ENDPROC(boot32_install_vc_handler)


boot32_vc_handler:
	/*
	 * We don't implement legacy booting with SEV-ES yet, so just hang the
	 * machine.
	 */
1:	hlt
	jmp 1b
	iret

	.code64
ENTRY(set_sev_encryption_mask)
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
ENDPROC(set_sev_encryption_mask)

#ifdef CONFIG_AMD_SEV_ES_GUEST
ENTRY(install_boot_vc_handler)
	BOOT_IDT_ENTRY BOOT_VECTOR_VC boot_vc_handler lm=1
	ret
ENDPROC(install_boot_vc_handler)

.macro EXCEPTION_HANDLER name function error_code=0
\name:
	/* Build pt_regs */
	.if \error_code == 0
	pushq	$0
	.endif

	pushq	%rdi
	pushq	%rsi
	pushq	%rdx
	pushq	%rcx
	pushq	%rax
	pushq	%r8
	pushq	%r9
	pushq	%r10
	pushq	%r11
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	/* Call handler with pt_regs */
	movq	%rsp, %rdi
	call	\function

	/* Restore regs */
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	popq	%r11
	popq	%r10
	popq	%r9
	popq	%r8
	popq	%rax
	popq	%rcx
	popq	%rdx
	popq	%rsi
	popq	%rdi

	/* Remove error code and return */
	addq	$8, %rsp
	iretq
.endm

EXCEPTION_HANDLER boot_vc_handler vc_handler error_code=1
#endif

	.data

#ifdef CONFIG_AMD_MEM_ENCRYPT
	.balign	8
GLOBAL(sme_me_mask)
	.quad	0
#endif

#ifdef CONFIG_AMD_SEV_ES_GUEST
	.balign	4096
GLOBAL(boot_ghcb)
	.fill	4096, 1, 0

	.balign	4096
GLOBAL(boot_ghcb_pt_pages)
	/* Need 3 pages to map the GHCB */
	.fill	3*4096, 1, 0
#endif

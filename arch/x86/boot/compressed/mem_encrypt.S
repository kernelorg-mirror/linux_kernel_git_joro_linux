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

/*
 * Emit code to request an CPUID register from the Hypervisor using
 * the MSR-based protocol.
 *
 * fn: The register containing the CPUID function
 * reg: Register requested
 *	1 = EAX
 *	2 = EBX
 *	3 = ECX
 *	4 = EDX
 *
 * Result is in EDX. Jumps to .Lfail on error
 */
.macro	SEV_ES_REQ_CPUID fn:req reg:req
	/* Request CPUID[%ebx].EAX */
	movl	$\reg, %eax
	shll	$30, %eax
	orl	$0x00000004, %eax
	movl	\fn, %edx
	movl	$MSR_AMD64_SEV_ES_GHCB, %ecx
	wrmsr
	rep; vmmcall
	rdmsr
	/* Check response code */
	andl	$0xfff, %eax
	cmpl	$5, %eax
	jne	.Lfail
	/* All good */
.endm

SYM_CODE_START(startup32_vc_handler)
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx

	/* Keep CPUID function in %ebx */
	movl	%eax, %ebx

	/* Check if error-code == SVM_EXIT_CPUID */
	cmpl	$0x72, 16(%esp)
	jne	.Lfail

	/* Request CPUID[%ebx].EAX */
	SEV_ES_REQ_CPUID fn=%ebx reg=0
	movl	%edx, 12(%esp)

	/* Request CPUID[%ebx].EBX */
	SEV_ES_REQ_CPUID fn=%ebx reg=1
	movl	%edx, 8(%esp)

	/* Request CPUID[%ebx].ECX */
	SEV_ES_REQ_CPUID fn=%ebx reg=2
	movl	%edx, 4(%esp)

	/* Request CPUID[%ebx].EDX */
	SEV_ES_REQ_CPUID fn=%ebx reg=3
	movl	%edx, (%esp)

	/*
	 * Sanity check CPUID results from the Hypervisor. See comment in
	 * do_vc_no_ghcb() for more details on why this is necessary.
	 */

	/* Fail if Hypervisor bit not set in CPUID[1].ECX[31] */
	cmpl    $1, %ebx
	jne     .Lcheck_leaf
	btl     $31, 4(%esp)
	jnc     .Lfail
	jmp     .Ldone

.Lcheck_leaf:
	/* Fail if SEV leaf not available in CPUID[0x80000000].EAX */
	cmpl    $0x80000000, %ebx
	jne     .Lcheck_sev
	cmpl    $0x8000001f, 12(%esp)
	jb      .Lfail
	jmp     .Ldone

.Lcheck_sev:
	/* Fail if SEV bit not set in CPUID[0x8000001f].EAX[1] */
	cmpl    $0x8000001f, %ebx
	jne     .Ldone
	btl     $1, 12(%esp)
	jnc     .Lfail

.Ldone:
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%eax

	/* Remove error code */
	addl	$4, %esp

	/* Jump over CPUID instruction */
	addl	$2, (%esp)

	iret
.Lfail:
	/* Send terminate request to Hypervisor */
	movl    $0x100, %eax
	xorl    %edx, %edx
	movl    $MSR_AMD64_SEV_ES_GHCB, %ecx
	wrmsr
	rep; vmmcall

	/* If request fails, go to hlt loop */
	hlt
	jmp .Lfail
SYM_CODE_END(startup32_vc_handler)

	.code64

#include "../../kernel/sev_verify_cbit.S"
SYM_FUNC_START(set_sev_encryption_mask)
#ifdef CONFIG_AMD_MEM_ENCRYPT
	push	%rbp
	push	%rdx

	movq	%rsp, %rbp		/* Save current stack pointer */

	call	get_sev_encryption_bit	/* Get the encryption bit position */
	testl	%eax, %eax
	jz	.Lno_sev_mask

	bts	%rax, sme_me_mask(%rip)	/* Create the encryption mask */

	/*
	 * Read MSR_AMD64_SEV again and store it to sev_status. Can't do this in
	 * get_sev_encryption_bit() because this function is 32-bit code and
	 * shared between 64-bit and 32-bit boot path.
	 */
	movl	$MSR_AMD64_SEV, %ecx	/* Read the SEV MSR */
	rdmsr

	/* Store MSR value in sev_status */
	shlq	$32, %rdx
	orq	%rdx, %rax
	movq	%rax, sev_status(%rip)

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
SYM_DATA(sme_me_mask,		.quad 0)
SYM_DATA(sev_status,		.quad 0)
SYM_DATA(sev_check_data,	.quad 0)
#endif

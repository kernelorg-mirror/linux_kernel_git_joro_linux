/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *	sev_verify_cbit.S - Code for verification of the C-bit position reported
 *			    by the Hypervisor when running with SEV enabled.
 *
 *	Copyright (c) 2020  Joerg Roedel (jroedel@suse.de)
 *
 * Implements sev_verify_cbit() which is called before switching to a new
 * long-mode page-table at boot.
 *
 * It verifies that the C-bit position is correct by writing a random value to
 * an encrypted memory location while on the current page-table. Then it
 * switches to the new page-table to verify the memory contents is still the
 * same. After that it switches back to the current page-table and when the
 * check succeeded it returns. If the check failed the code invalidates the
 * stack pointer and goes into a hlt loop. The stack-pointer is invalidated to
 * make sure no interrupt or exception can get the CPU out of the hlt loop.
 *
 * New page-table pointer is expected in %rdi (first parameter)
 *
 */
SYM_FUNC_START(sev_verify_cbit)
#ifdef CONFIG_AMD_MEM_ENCRYPT
	/* First check if a C-bit was detected */
	movq	sme_me_mask(%rip), %r10
	testq	%r10, %r10
	jz	3f

	/* sme_me_mask != 0 could mean SME or SEV - Check also for SEV */
	movq	sev_status(%rip), %r10
	testq	%r10, %r10
	jz	3f

	/*
	 * Verified that running under SEV - now get a random value using
	 * RDRAND. This instruction is mandatory when running as an SEV guest.
	 *
	 * Don't bail out of the loop if RDRAND returns errors. It is better to
	 * prevent forward progress than to work with a non-random value here.
	 */
1:	rdrand	%r10
	jnc	1b

	/* Store value to memory and keep it in %r10 */
	movq	%r10, sev_check_data(%rip)

	/* Backup current %cr3 value to restore it later */
	movq	%cr3, %r11

	/* Switch to new %cr3 - This might unmap the stack */
	movq	%rdi, %cr3

	/*
	 * Compare value in %r10 with memory location - If C-Bit is incorrect
	 * this would read the encrypted data and make the check fail.
	 */
	cmpq	%r10, sev_check_data(%rip)

	/* Restore old %cr3 */
	movq	%r11, %cr3

	/* Check CMPQ result */
	je	3f

	/*
	 * The check failed - Prevent any forward progress to prevent ROP
	 * attacks, invalidate the stack and go into a hlt loop.
	 */
	xorq	%rsp, %rsp
	subq	$0x1000, %rsp
2:	hlt
	jmp 2b
3:
#endif
	ret
SYM_FUNC_END(sev_verify_cbit)


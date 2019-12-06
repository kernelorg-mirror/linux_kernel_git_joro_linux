/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 *
 * This file is not compiled stand-alone. It contains code shared
 * between the pre-decompression boot code and the running Linux kernel
 * and is included directly into both code-bases.
 */

/*
 * Boot VC Handler - This is the first VC handler during boot, there is no GHCB
 * page yet, so it only supports the MSR based communication with the
 * hypervisor and only the CPUID exit-code.
 */
void __init no_ghcb_vc_handler(struct pt_regs *regs)
{
	unsigned long val, old_val = read_ghcb_msr();
	unsigned long exit_code = regs->orig_ax;
	unsigned fn = lower_bits(regs->ax, 32);

	/* Only CPUID is supported via MSR protocol */
	if (exit_code != SVM_EXIT_CPUID)
		goto fail;

	write_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EAX));
	VMGEXIT();
	val = read_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->ax = copy_lower_bits(regs->ax, val >> 32, 32);

	write_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EBX));
	VMGEXIT();
	val = read_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->bx = copy_lower_bits(regs->bx, val >> 32, 32);

	write_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_ECX));
	VMGEXIT();
	val = read_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->cx = copy_lower_bits(regs->cx, val >> 32, 32);

	write_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EDX));
	VMGEXIT();
	val = read_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->dx = copy_lower_bits(regs->dx, val >> 32, 32);

	regs->ip += 2;

	write_ghcb_msr(old_val);

	return;

fail:
	write_ghcb_msr(GHCB_SEV_TERMINATE);
	VMGEXIT();

	/* Shouldn't get here - if we do halt the machine */
	while (true)
		asm volatile("hlt\n");
}

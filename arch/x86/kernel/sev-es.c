// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 SUSE
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include <linux/sched/debug.h>	/* For show_regs() */
#include <linux/percpu-defs.h>
#include <linux/mem_encrypt.h>
#include <linux/printk.h>
#include <linux/set_memory.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include <asm/trap_defs.h>
#include <asm/sev-es.h>
#include <asm/fpu/internal.h>
#include <asm/processor.h>
#include <asm/traps.h>
#include <asm/svm.h>

#define DR7_RESET_VALUE        0x400

/* For early boot hypervisor communication in SEV-ES enabled guests */
struct ghcb boot_ghcb_page __bss_decrypted __aligned(PAGE_SIZE);

/*
 * Needs to be in the .data section because we need it NULL before bss is
 * cleared
 */
struct ghcb __initdata *boot_ghcb;
static DEFINE_PER_CPU(unsigned long, cached_dr7) = DR7_RESET_VALUE;
/* Needed before per-cpu access is set up */
static unsigned long early_dr7 = DR7_RESET_VALUE;

struct ghcb_state {
	struct ghcb *ghcb;
};

/* Runtime GHCB pointers */
static struct ghcb __percpu *ghcb_page;

/*
 * Mark the per-cpu GHCB as in-use to detect nested #VC exceptions.
 * There is no need for it to be atomic, because nothing is written to the GHCB
 * between the read and the write of ghcb_active. So it is safe to use it when a
 * nested #VC exception happens before the write.
 */
static DEFINE_PER_CPU(bool, ghcb_active);

static struct ghcb* sev_es_get_ghcb(struct ghcb_state *state)
{
	struct ghcb *ghcb = (struct ghcb *)this_cpu_ptr(ghcb_page);
	bool *active = this_cpu_ptr(&ghcb_active);

	if (unlikely(*active)) {
		/* GHCB is already in use - save its contents */

		state->ghcb = kzalloc(sizeof(struct ghcb), GFP_ATOMIC);
		if (!state->ghcb)
			return NULL;

		*state->ghcb = *ghcb;
	} else {
		state->ghcb = NULL;
		*active = true;
	}

	return ghcb;
}

static void sev_es_put_ghcb(struct ghcb_state *state)
{
	bool *active = this_cpu_ptr(&ghcb_active);
	struct ghcb *ghcb = (struct ghcb *)this_cpu_ptr(ghcb_page);

	if (state->ghcb) {
		/* Restore saved state and free backup memory */
		*ghcb = *state->ghcb;
		kfree(state->ghcb);
		state->ghcb = NULL;
	} else {
		*active = false;
	}
}

/* Needed in vc_early_vc_forward_exception */
extern void early_exception(struct pt_regs *regs, int trapnr);

static inline u64 sev_es_rd_ghcb_msr(void)
{
	return native_read_msr(MSR_AMD64_SEV_ES_GHCB);
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = (u32)(val);
	high = (u32)(val >> 32);

	native_write_msr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

static bool vc_check_kernel(struct pt_regs *regs)
{
	return regs->cs == __KERNEL_CS;
}

static enum es_result vc_fetch_insn_byte(struct es_em_ctxt *ctxt,
					 unsigned int offset,
					 char *buffer)
{
	if (user_mode(ctxt->regs)) {
		unsigned long addr = ctxt->regs->ip + offset;
		char __user *rip = (char __user *)addr;

		if (unlikely(addr >= TASK_SIZE_MAX))
			return ES_UNSUPPORTED;

		if (copy_from_user(buffer + offset, rip, 1)) {
			ctxt->fi.vector     = X86_TRAP_PF;
			ctxt->fi.cr2        = addr;
			ctxt->fi.error_code = X86_PF_INSTR | X86_PF_USER;
			return ES_EXCEPTION;
		}
	} else {
		char *rip = (char *)ctxt->regs->ip + offset;

		if (probe_kernel_read(buffer + offset, rip, 1) != 0) {
			ctxt->fi.vector     = X86_TRAP_PF;
			ctxt->fi.cr2        = (unsigned long)rip;
			ctxt->fi.error_code = X86_PF_INSTR;
			return ES_EXCEPTION;
		}
	}

	return ES_OK;
}

static enum es_result vc_write_mem(struct es_em_ctxt *ctxt,
				   void *dst, char *buf, size_t size)
{
	/* More checks are needed when we boot to user-space */
	if (!vc_check_kernel(ctxt->regs))
		return ES_UNSUPPORTED;

	memcpy(dst, buf, size);

	return ES_OK;
}

static enum es_result vc_read_mem(struct es_em_ctxt *ctxt,
				  void *src, char *buf, size_t size)
{
	/* More checks are needed when we boot to user-space */
	if (!vc_check_kernel(ctxt->regs))
		return ES_UNSUPPORTED;

	memcpy(buf, src, size);

	return ES_OK;
}

static phys_addr_t vc_slow_virt_to_phys(struct ghcb *ghcb, long vaddr)
{
	unsigned long va = (unsigned long)vaddr;
	unsigned int level;
	phys_addr_t pa;
	pgd_t *pgd;
	pte_t *pte;

	pgd = pgd_offset(current->active_mm, va);
	pte = lookup_address_in_pgd(pgd, va, &level);
	if (!pte)
		return 0;

	pa = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
	pa |= va & ~page_level_mask(level);

	return pa;
}

/* Include code shared with pre-decompression boot stage */
#include "sev-es-shared.c"

static enum es_result vc_handle_msr(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	struct pt_regs *regs = ctxt->regs;
	enum es_result ret;
	bool write;
	u64 exit_info_1;

	write = (ctxt->insn.opcode.bytes[1] == 0x30);

	ghcb_set_rcx(ghcb, regs->cx);
	if (write) {
		ghcb_set_rax(ghcb, regs->ax);
		ghcb_set_rdx(ghcb, regs->dx);
		exit_info_1 = 1;
	} else {
		exit_info_1 = 0;
	}

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_MSR, exit_info_1, 0);
	if (ret != ES_OK)
		return ret;
	else if (!write) {
		regs->ax = ghcb->save.rax;
		regs->dx = ghcb->save.rdx;
	}

	return ret;
}

/*
 * This function runs on the first #VC exception after the kernel
 * switched to virtual addresses.
 */
static bool __init sev_es_setup_ghcb(void)
{
	/* First make sure the hypervisor talks a supported protocol. */
	if (!sev_es_negotiate_protocol())
		return false;
	/*
	 * Clear the boot_ghcb. The first exception comes in before the bss
	 * section is cleared.
	 */
	memset(&boot_ghcb_page, 0, PAGE_SIZE);

	/* Alright - Make the boot-ghcb public */
	boot_ghcb = &boot_ghcb_page;

	return true;
}

void sev_es_init_ghcbs(void)
{
	int cpu;

	if (!sev_es_active())
		return;

	/* Allocate GHCB pages */
	ghcb_page = __alloc_percpu(sizeof(struct ghcb), PAGE_SIZE);

	/* Initialize per-cpu GHCB pages */
	for_each_possible_cpu(cpu) {
		struct ghcb *ghcb = (struct ghcb *)per_cpu_ptr(ghcb_page, cpu);

		set_memory_decrypted((unsigned long)ghcb,
				     sizeof(*ghcb) >> PAGE_SHIFT);
		memset(ghcb, 0, sizeof(*ghcb));
	}
}

static void __init vc_early_vc_forward_exception(struct es_em_ctxt *ctxt)
{
	int trapnr = ctxt->fi.vector;

	if (trapnr == X86_TRAP_PF)
		native_write_cr2(ctxt->fi.cr2);

	ctxt->regs->orig_ax = ctxt->fi.error_code;
	early_exception(ctxt->regs, trapnr);
}

static enum es_result vc_handle_dr7_write(struct ghcb *ghcb,
					  struct es_em_ctxt *ctxt,
					  bool early)
{
	u8 rm = X86_MODRM_RM(ctxt->insn.modrm.value);
	unsigned long *reg;
	enum es_result ret;

	if (ctxt->insn.rex_prefix.nbytes &&
	    X86_REX_B(ctxt->insn.rex_prefix.value))
		rm |= 0x8;

	reg = vc_register_from_idx(ctxt->regs, rm);

	/* Using a value of 0 for ExitInfo1 means RAX holds the value */
	ghcb_set_rax(ghcb, *reg);
	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_WRITE_DR7, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (early)
		early_dr7 = *reg;
	else
		this_cpu_write(cached_dr7, *reg);

	return ES_OK;
}

static enum es_result vc_handle_dr7_read(struct ghcb *ghcb,
					 struct es_em_ctxt *ctxt,
					 bool early)
{
	u8 rm = X86_MODRM_RM(ctxt->insn.modrm.value);
	unsigned long *reg;

	if (ctxt->insn.rex_prefix.nbytes &&
	    X86_REX_B(ctxt->insn.rex_prefix.value))
		rm |= 0x8;

	reg = vc_register_from_idx(ctxt->regs, rm);

	if (early)
		*reg = early_dr7;
	else
		*reg = this_cpu_read(cached_dr7);

	return ES_OK;
}

static enum es_result vc_handle_wbinvd(struct ghcb *ghcb,
				       struct es_em_ctxt *ctxt)
{
	return sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_WBINVD, 0, 0);
}

static enum es_result vc_handle_exitcode(struct es_em_ctxt *ctxt,
					 struct ghcb *ghcb,
					 unsigned long exit_code,
					 bool early)
{
	enum es_result result;

	switch (exit_code) {
	case SVM_EXIT_READ_DR7:
		result = vc_handle_dr7_read(ghcb, ctxt, early);
		break;
	case SVM_EXIT_WRITE_DR7:
		result = vc_handle_dr7_write(ghcb, ctxt, early);
		break;
	case SVM_EXIT_CPUID:
		result = vc_handle_cpuid(ghcb, ctxt);
		break;
	case SVM_EXIT_IOIO:
		result = vc_handle_ioio(ghcb, ctxt);
		break;
	case SVM_EXIT_MSR:
		result = vc_handle_msr(ghcb, ctxt);
		break;
	case SVM_EXIT_WBINVD:
		result = vc_handle_wbinvd(ghcb, ctxt);
		break;
	case SVM_EXIT_NPF:
		result = vc_handle_mmio(ghcb, ctxt);
		break;
	default:
		/*
		 * Unexpected #VC exception
		 */
		result = ES_UNSUPPORTED;
	}

	return result;
}

static enum es_result vc_context_filter(struct pt_regs *regs, long exit_code)
{
	enum es_result r = ES_OK;

	if (user_mode(regs)) {
		switch (exit_code) {
		/* List of #VC exit-codes we support in user-space */
		case SVM_EXIT_EXCP_BASE ... SVM_EXIT_LAST_EXCP:
		case SVM_EXIT_CPUID:
			r = ES_OK;
			break;
		default:
			r = ES_UNSUPPORTED;
			break;
		}
	}

	return r;
}

static void vc_forward_exception(struct es_em_ctxt *ctxt)
{
	long error_code = ctxt->fi.error_code;
	int trapnr = ctxt->fi.vector;

	ctxt->regs->orig_ax = ctxt->fi.error_code;

	switch (trapnr) {
	case X86_TRAP_GP:
		do_general_protection(ctxt->regs, error_code);
		break;
	case X86_TRAP_UD:
		do_invalid_op(ctxt->regs, 0);
		break;
	default:
		BUG();
	}
}

dotraplinkage void do_vmm_communication(struct pt_regs *regs, unsigned long exit_code)
{
	struct ghcb_state state;
	struct es_em_ctxt ctxt;
	enum es_result result;
	struct ghcb *ghcb;

	/*
	 * This is invoked through an interrupt gate, so IRQs are disabled. The
	 * code below might walk page-tables for user or kernel addresses, so
	 * keep the IRQs disabled to protect us against concurrent TLB flushes.
	 */

	ghcb = sev_es_get_ghcb(&state);
	if (!ghcb) {
		/* This can only fail on an allocation error, so just retry */
		result = ES_RETRY;
	} else {
		vc_ghcb_invalidate(ghcb);
		result = vc_init_em_ctxt(&ctxt, regs, exit_code);
	}

	/* Check if the exception is supported in the context we came from. */
	if (result == ES_OK)
		result = vc_context_filter(regs, exit_code);

	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, ghcb, exit_code, false);

	sev_es_put_ghcb(&state);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		vc_finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		pr_err_ratelimited("Unsupported exit-code 0x%02lx in early #VC exception (IP: 0x%lx)\n",
				   exit_code, regs->ip);
		goto fail;
	case ES_VMM_ERROR:
		pr_err_ratelimited("Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
				   exit_code, regs->ip);
		goto fail;
	case ES_DECODE_FAILED:
		pr_err_ratelimited("PANIC: Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
				   exit_code, regs->ip);
		goto fail;
	case ES_EXCEPTION:
		vc_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		BUG();
	}

	return;

fail:
	if (user_mode(regs)) {
		/*
		 * Do not kill the machine if user-space triggered the
		 * exception. Send SIGBUS instead and let user-space deal with
		 * it.
		 */
		force_sig_fault(SIGBUS, BUS_OBJERR, (void __user *)0);
	} else {
		/* Show some debug info */
		show_regs(regs);

		/* Ask hypervisor to sev_es_terminate */
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

		/* If that fails and we get here - just halt the machine */
		while (true)
			halt();
	}
}

bool __init boot_vc_exception(struct pt_regs *regs)
{
	unsigned long exit_code = regs->orig_ax;
	struct es_em_ctxt ctxt;
	enum es_result result;

	/* Do initial setup or terminate the guest */
	if (unlikely(boot_ghcb == NULL && !sev_es_setup_ghcb()))
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	vc_ghcb_invalidate(boot_ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, exit_code);

	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, boot_ghcb, exit_code, true);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		vc_finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		early_printk("PANIC: Unsupported exit-code 0x%02lx in early #VC exception (IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_VMM_ERROR:
		early_printk("PANIC: Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_DECODE_FAILED:
		early_printk("PANIC: Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
				exit_code, regs->ip);
		goto fail;
	case ES_EXCEPTION:
		vc_early_vc_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		BUG();
	}

	return true;

fail:
	show_regs(regs);

	while (true)
		halt();
}

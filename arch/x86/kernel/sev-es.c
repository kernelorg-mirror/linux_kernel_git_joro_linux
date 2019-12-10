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

/* For early boot hypervisor communication in SEV-ES enabled guests */
struct ghcb boot_ghcb_page __bss_decrypted __aligned(PAGE_SIZE);

/*
 * Needs to be in the .data section because we need it NULL before bss is
 * cleared
 */
struct ghcb __initdata *boot_ghcb;

/* Runtime GHCBs */
static DEFINE_PER_CPU_DECRYPTED(struct ghcb, ghcb_page) __aligned(PAGE_SIZE);

/* Needed in early_forward_exception */
extern void early_exception(struct pt_regs *regs, int trapnr);

static inline u64 read_ghcb_msr(void)
{
	return native_read_msr(MSR_AMD64_SEV_ES_GHCB);
}

static inline void write_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = (u32)(val);
	high = (u32)(val >> 32);

	native_write_msr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

static bool check_kernel(struct pt_regs *regs)
{
	return regs->cs == __KERNEL_CS;
}

static enum es_result es_fetch_insn_byte(struct es_em_ctxt *ctxt,
					 unsigned int offset,
					 char *buffer)
{
	char *rip = (char *)ctxt->regs->ip;

	/* More checks are needed when we boot to user-space */
	if (!check_kernel(ctxt->regs))
		return ES_UNSUPPORTED;

	buffer[offset] = rip[offset];

	return ES_OK;
}

static enum es_result es_write_mem(struct es_em_ctxt *ctxt,
				   void *dst, char *buf, size_t size)
{
	/* More checks are needed when we boot to user-space */
	if (!check_kernel(ctxt->regs))
		return ES_UNSUPPORTED;

	memcpy(dst, buf, size);

	return ES_OK;
}

static enum es_result es_read_mem(struct es_em_ctxt *ctxt,
				  void *src, char *buf, size_t size)
{
	/* More checks are needed when we boot to user-space */
	if (!check_kernel(ctxt->regs))
		return ES_UNSUPPORTED;

	memcpy(buf, src, size);

	return ES_OK;
}

static phys_addr_t es_slow_virt_to_phys(struct ghcb *ghcb, long vaddr)
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

/*
 * This function runs on the first #VC exception after the kernel
 * switched to virtual addresses.
 */
static bool __init setup_ghcb(void)
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

void encrypted_state_init_ghcbs(void)
{
	int cpu;

	if (!sev_es_active())
		return;

	/* Initialize per-cpu GHCB pages */
	for_each_possible_cpu(cpu) {
		struct ghcb *ghcb = &per_cpu(ghcb_page, cpu);

		set_memory_decrypted((unsigned long)ghcb,
				     sizeof(ghcb_page) >> PAGE_SHIFT);
		memset(ghcb, 0, sizeof(*ghcb));
	}
}

static void __init early_forward_exception(struct es_em_ctxt *ctxt)
{
	int trapnr = ctxt->fi.vector;

	if (trapnr == X86_TRAP_PF)
		native_write_cr2(ctxt->fi.cr2);

	ctxt->regs->orig_ax = ctxt->fi.error_code;
	early_exception(ctxt->regs, trapnr);
}

static enum es_result handle_vc_exception(struct es_em_ctxt *ctxt,
		struct ghcb *ghcb,
		unsigned long exit_code)
{
	enum es_result result;

	switch (exit_code) {
	case SVM_EXIT_CPUID:
		result = handle_cpuid(ghcb, ctxt);
		break;
	case SVM_EXIT_IOIO:
		result = handle_ioio(ghcb, ctxt);
		break;
	case SVM_EXIT_NPF:
		result = handle_mmio(ghcb, ctxt);
		break;
	default:
		/*
		 * Unexpected #VC exception
		 */
		result = ES_UNSUPPORTED;
	}

	return result;
}

static void forward_exception(struct es_em_ctxt *ctxt)
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
	struct es_em_ctxt ctxt;
	enum es_result result;
	struct ghcb *ghcb;

	/*
	 * This is invoked through an interrupt gate, so IRQs are disabled. The
	 * code below might walk page-tables for user or kernel addresses, so
	 * keep the IRQs disabled to protect us against concurrent TLB flushes.
	 */

	ghcb = this_cpu_ptr(&ghcb_page);

	ghcb_invalidate(ghcb);
	result = init_em_ctxt(&ctxt, regs, exit_code);

	if (result == ES_OK)
		result = handle_vc_exception(&ctxt, ghcb, exit_code);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		pr_emerg("Unsupported exit-code 0x%02lx in early #VC exception (IP: 0x%lx)\n",
			 exit_code, regs->ip);
		goto fail;
	case ES_VMM_ERROR:
		pr_emerg("PANIC: Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
			 exit_code, regs->ip);
		goto fail;
	case ES_DECODE_FAILED:
		pr_emerg("PANIC: Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
			 exit_code, regs->ip);
		goto fail;
	case ES_EXCEPTION:
		forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		BUG();
	}

	return;

fail:
	show_regs(regs);

	while (true)
		halt();
}

int __init boot_vc_exception(struct pt_regs *regs)
{
	unsigned long exit_code = regs->orig_ax;
	struct es_em_ctxt ctxt;
	enum es_result result;

	/* Do initial setup or terminate the guest */
	if (unlikely(boot_ghcb == NULL && !setup_ghcb()))
		terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	ghcb_invalidate(boot_ghcb);
	result = init_em_ctxt(&ctxt, regs, exit_code);

	if (result == ES_OK)
		result = handle_vc_exception(&ctxt, boot_ghcb, exit_code);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		finish_insn(&ctxt);
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
		early_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		BUG();
	}

	return 0;

fail:
	show_regs(regs);

	while (true)
		halt();
}

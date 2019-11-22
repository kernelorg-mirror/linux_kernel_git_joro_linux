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
#include <asm/insn-eval.h>
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

static struct ghcb *sev_es_get_ghcb(struct ghcb_state *state)
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

static int vc_fetch_insn_kernel(struct es_em_ctxt *ctxt,
				unsigned char *buffer)
{
	return probe_kernel_read(buffer, (unsigned char *)ctxt->regs->ip,
				 MAX_INSN_SIZE);
}

static enum es_result vc_decode_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	enum es_result ret;
	int res;

	if (!user_mode(ctxt->regs)) {
		res = vc_fetch_insn_kernel(ctxt, buffer);
		if (unlikely(res == -EFAULT)) {
			ctxt->fi.vector     = X86_TRAP_PF;
			ctxt->fi.error_code = 0;
			ctxt->fi.cr2        = ctxt->regs->ip;
			return ES_EXCEPTION;
		}

		insn_init(&ctxt->insn, buffer, MAX_INSN_SIZE - res, 1);
		insn_get_length(&ctxt->insn);
	} else {
		res = insn_fetch_from_user(ctxt->regs, buffer);
		if (res == 0) {
			ctxt->fi.vector     = X86_TRAP_PF;
			ctxt->fi.cr2        = ctxt->regs->ip;
			ctxt->fi.error_code = X86_PF_INSTR | X86_PF_USER;
			return ES_EXCEPTION;
		}

		if (!insn_decode(ctxt->regs, &ctxt->insn, buffer, res))
			return ES_DECODE_FAILED;
	}

	ret = ctxt->insn.immediate.got ? ES_OK : ES_DECODE_FAILED;

	return ret;
}

static enum es_result vc_write_mem(struct es_em_ctxt *ctxt,
				   char *dst, char *buf, size_t size)
{
	unsigned long error_code = X86_PF_PROT | X86_PF_WRITE;
	unsigned char *target = dst;
	u64 d8;
	u32 d4;
	u16 d2;
	u8  d1;

	switch (size) {
	case 1:
		memcpy(&d1, buf, 1);
		if (put_user(d1, target))
			goto fault;
		break;
	case 2:
		memcpy(&d2, buf, 2);
		if (put_user(d2, target))
			goto fault;
		break;
	case 4:
		memcpy(&d4, buf, 4);
		if (put_user(d4, target))
			goto fault;
		break;
	case 8:
		memcpy(&d8, buf, 8);
		if (put_user(d8, target))
			goto fault;
		break;
	default:
		WARN_ONCE(1, "%s: Invalid size: %zu\n", __func__, size);
		return ES_UNSUPPORTED;
	}

	return ES_OK;

fault:
	if (user_mode(ctxt->regs))
		error_code |= X86_PF_USER;

	ctxt->fi.vector = X86_TRAP_PF;
	ctxt->fi.error_code = error_code;
	ctxt->fi.cr2 = (unsigned long)dst;

	return ES_EXCEPTION;
}

static enum es_result vc_read_mem(struct es_em_ctxt *ctxt,
				  char *src, char *buf, size_t size)
{
	unsigned long error_code = X86_PF_PROT;
	u64 d8;
	u32 d4;
	u16 d2;
	u8  d1;

	switch (size) {
	case 1:
		if (get_user(d1, src))
			goto fault;
		memcpy(buf, &d1, 1);
		break;
	case 2:
		if (get_user(d2, src))
			goto fault;
		memcpy(buf, &d2, 2);
		break;
	case 4:
		if (get_user(d4, src))
			goto fault;
		memcpy(buf, &d4, 4);
		break;
	case 8:
		if (get_user(d8, src))
			goto fault;
		memcpy(buf, &d8, 8);
		break;
	default:
		WARN_ONCE(1, "%s: Invalid size: %zu\n", __func__, size);
		return ES_UNSUPPORTED;
	}

	return ES_OK;

fault:
	if (user_mode(ctxt->regs))
		error_code |= X86_PF_USER;

	ctxt->fi.vector = X86_TRAP_PF;
	ctxt->fi.error_code = error_code;
	ctxt->fi.cr2 = (unsigned long)src;

	return ES_EXCEPTION;
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

static long *vc_insn_get_reg(struct es_em_ctxt *ctxt)
{
	long *reg_array;
	int offset;

	reg_array = (long *)ctxt->regs;
	offset    = insn_get_modrm_reg_off(&ctxt->insn, ctxt->regs);

	if (offset < 0)
		return NULL;

	offset /= sizeof(long);

	return reg_array + offset;
}

static enum es_result vc_do_mmio(struct ghcb *ghcb, struct es_em_ctxt *ctxt,
				 unsigned int bytes, bool read)
{
	u64 exit_code, exit_info_1, exit_info_2;
	unsigned long ghcb_pa = __pa(ghcb);
	void __user *ref;

	ref = insn_get_addr_ref(&ctxt->insn, ctxt->regs);
	if (ref == (void __user *)-1L)
		return ES_UNSUPPORTED;

	exit_code = read ? SVM_VMGEXIT_MMIO_READ : SVM_VMGEXIT_MMIO_WRITE;

	exit_info_1 = vc_slow_virt_to_phys(ghcb, (long)ref);
	exit_info_2 = bytes;    /* Can never be greater than 8 */

	ghcb->save.sw_scratch = ghcb_pa + offsetof(struct ghcb, shared_buffer);

	return sev_es_ghcb_hv_call(ghcb, ctxt, exit_code, exit_info_1, exit_info_2);
}

static enum es_result vc_handle_mmio_twobyte_ops(struct ghcb *ghcb,
						 struct es_em_ctxt *ctxt)
{
	struct insn *insn = &ctxt->insn;
	unsigned int bytes = 0;
	enum es_result ret;
	int sign_byte;
	long *reg_data;

	switch (insn->opcode.bytes[1]) {
		/* MMIO Read w/ zero-extension */
	case 0xb6:
		bytes = 1;
		/* Fallthrough */
	case 0xb7:
		if (!bytes)
			bytes = 2;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		/* Zero extend based on operand size */
		reg_data = vc_insn_get_reg(ctxt);
		memset(reg_data, 0, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

		/* MMIO Read w/ sign-extension */
	case 0xbe:
		bytes = 1;
		/* Fallthrough */
	case 0xbf:
		if (!bytes)
			bytes = 2;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		/* Sign extend based on operand size */
		reg_data = vc_insn_get_reg(ctxt);
		if (bytes == 1) {
			u8 *val = (u8 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x80) ? 0x00 : 0xff;
		} else {
			u16 *val = (u16 *)ghcb->shared_buffer;

			sign_byte = (*val & 0x8000) ? 0x00 : 0xff;
		}
		memset(reg_data, sign_byte, insn->opnd_bytes);

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

	default:
		ret = ES_UNSUPPORTED;
	}

	return ret;
}

static enum es_result vc_handle_mmio(struct ghcb *ghcb,
				     struct es_em_ctxt *ctxt)
{
	struct insn *insn = &ctxt->insn;
	unsigned int bytes = 0;
	enum es_result ret;
	long *reg_data;

	switch (insn->opcode.bytes[0]) {
	/* MMIO Write */
	case 0x88:
		bytes = 1;
		/* Fallthrough */
	case 0x89:
		if (!bytes)
			bytes = insn->opnd_bytes;

		reg_data = vc_insn_get_reg(ctxt);
		memcpy(ghcb->shared_buffer, reg_data, bytes);

		ret = vc_do_mmio(ghcb, ctxt, bytes, false);
		break;

	case 0xc6:
		bytes = 1;
		/* Fallthrough */
	case 0xc7:
		if (!bytes)
			bytes = insn->opnd_bytes;

		memcpy(ghcb->shared_buffer, insn->immediate1.bytes, bytes);

		ret = vc_do_mmio(ghcb, ctxt, bytes, false);
		break;

		/* MMIO Read */
	case 0x8a:
		bytes = 1;
		/* Fallthrough */
	case 0x8b:
		if (!bytes)
			bytes = insn->opnd_bytes;

		ret = vc_do_mmio(ghcb, ctxt, bytes, true);
		if (ret)
			break;

		reg_data = vc_insn_get_reg(ctxt);
		if (bytes == 4)
			*reg_data = 0;  /* Zero-extend for 32-bit operation */

		memcpy(reg_data, ghcb->shared_buffer, bytes);
		break;

		/* Two-Byte Opcodes */
	case 0x0f:
		ret = vc_handle_mmio_twobyte_ops(ghcb, ctxt);
		break;
	default:
		ret = ES_UNSUPPORTED;
	}

	return ret;
}

static enum es_result vc_handle_exitcode(struct es_em_ctxt *ctxt,
		struct ghcb *ghcb,
		unsigned long exit_code)
{
	enum es_result result;

	switch (exit_code) {
	case SVM_EXIT_CPUID:
		result = vc_handle_cpuid(ghcb, ctxt);
		break;
	case SVM_EXIT_IOIO:
		result = vc_handle_ioio(ghcb, ctxt);
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
		result = vc_handle_exitcode(&ctxt, ghcb, exit_code);

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
		result = vc_handle_exitcode(&ctxt, boot_ghcb, exit_code);

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

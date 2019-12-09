// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 SUSE
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include <linux/kernel.h>
#include <linux/mm.h>

#include <asm/trap_defs.h>
#include <asm/sev-es.h>
#include <asm/fpu/internal.h>
#include <asm/processor.h>
#include <asm/svm.h>

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
	char *rip = (char *)ctxt->regs->ip;

	/* More checks are needed when we boot to user-space */
	if (!vc_check_kernel(ctxt->regs))
		return ES_UNSUPPORTED;

	buffer[offset] = rip[offset];

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

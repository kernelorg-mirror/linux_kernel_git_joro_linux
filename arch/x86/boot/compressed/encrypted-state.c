/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include <asm/encrypted-state.h>
#include <asm/msr-index.h>
#include <asm/ptrace.h>
#include <asm/svm.h>

#include "misc.h"

struct ghcb boot_ghcb_page __aligned(PAGE_SIZE);
struct ghcb *boot_ghcb;

static inline u64 read_ghcb_msr(void)
{
	unsigned long low, high;

	asm volatile("rdmsr\n" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV_ES_GHCB));

	return ((high << 32) | low);
}

static inline void write_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = val & 0xffffffffUL;
	high = val >> 32;

	asm volatile("wrmsr\n" : : "c" (MSR_AMD64_SEV_ES_GHCB),
			"a"(low), "d" (high) : "memory");
}

static enum es_result es_fetch_insn_byte(struct es_em_ctxt *ctxt,
					 unsigned int offset,
					 char *buffer)
{
	char *rip = (char *)ctxt->regs->ip;

	buffer[offset] = rip[offset];

	return ES_OK;
}

static enum es_result es_write_mem(struct es_em_ctxt *ctxt,
				   void *dst, char *buf, size_t size)
{
	memcpy(dst, buf, size);

	return ES_OK;
}

static enum es_result es_read_mem(struct es_em_ctxt *ctxt,
				  void *src, char *buf, size_t size)
{
	memcpy(buf, src, size);

	return ES_OK;
}

#undef __init
#undef __pa
#define __init
#define __pa(x)	((unsigned long)(x))

/* Basic instruction decoding support needed */
#include "../../lib/inat.c"
#include "../../lib/insn.c"

/* Include code for early handlers */
#include "../../kernel/encrypted-state-early.c"

static bool setup_ghcb(void)
{
	if (!sev_es_negotiate_protocol())
		terminate(GHCB_SEV_ES_REASON_PROTOCOL_UNSUPPORTED);

	if (set_page_decrypted((unsigned long)&boot_ghcb_page))
		return false;

	/* Page is now mapped decrypted, clear it */
	memset(&boot_ghcb_page, 0, sizeof(boot_ghcb_page));

	boot_ghcb = &boot_ghcb_page;

	return true;
}

void boot_vc_handler(struct pt_regs *regs)
{
	u64 exit_code = regs->orig_ax;
	struct es_em_ctxt ctxt;
	enum es_result result;

	if (!boot_ghcb && !setup_ghcb())
		terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

	init_em_ctxt(&ctxt, regs);
	ghcb_invalidate(boot_ghcb);

	switch (exit_code) {
	case SVM_EXIT_IOIO:
		result = handle_ioio(boot_ghcb, &ctxt);
		break;
	default:
		result = ES_UNSUPPORTED;
		break;
	}

	if (result == ES_OK) {
		finish_insn(&ctxt);
	} else if (result != ES_RETRY) {
		/*
		 * For now, just halt the machine. That makes debugging easier,
		 * later we just call terminate() here.
		 */
		while (true)
			asm volatile("hlt\n");
	}
}

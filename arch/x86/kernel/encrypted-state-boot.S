/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Encrypted State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include <linux/linkage.h>
#include <linux/init.h>

#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/processor-flags.h>
#include <asm/msr-index.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>

#include "../entry/calling.h"

	.text
	__HEAD
	.code64
SYM_CODE_START_NOALIGN(early_vc_handler)
	UNWIND_HINT_IRET_REGS offset=8
	/*
	 * VC Exception handler used during very early boot. The
	 * early_idt_handler_array can't be used because it returns via
	 * the paravirtualized INTERRUPT_RETURN and pv-ops don't work
	 * that early.
	 */

	/* Build pt_regs */
	PUSH_AND_CLEAR_REGS

	/* Call C handler */
	movq    %rsp, %rdi
	call    no_ghcb_vc_handler

	/* Unwind pt_regs */
	POP_REGS

	/* Remove Error Code */
	addq    $8, %rsp

	/* Pure iret required here - don't use INTERRUPT_RETURN */
	iretq
SYM_CODE_END(early_vc_handler)

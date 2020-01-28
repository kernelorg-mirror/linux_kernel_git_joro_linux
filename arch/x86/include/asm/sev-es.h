/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#ifndef __ASM_ENCRYPTED_STATE_H
#define __ASM_ENCRYPTED_STATE_H

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <asm/insn.h>

#define GHCB_SEV_INFO		0x001UL
#define GHCB_SEV_INFO_REQ	0x002UL
#define		GHCB_INFO(v)		((v) & 0xfffUL)
#define		GHCB_PROTO_MAX(v)	(((v) >> 48) & 0xffffUL)
#define		GHCB_PROTO_MIN(v)	(((v) >> 32) & 0xffffUL)
#define		GHCB_PROTO_OUR		0x0001UL
#define GHCB_SEV_CPUID_REQ	0x004UL
#define		GHCB_CPUID_REQ_EAX	0
#define		GHCB_CPUID_REQ_EBX	1
#define		GHCB_CPUID_REQ_ECX	2
#define		GHCB_CPUID_REQ_EDX	3
#define		GHCB_CPUID_REQ(fn, reg) (GHCB_SEV_CPUID_REQ | \
					(((unsigned long)reg & 3) << 30) | \
					(((unsigned long)fn) << 32))

#define GHCB_SEV_CPUID_RESP	0x005UL
#define GHCB_SEV_TERMINATE	0x100UL
#define		GHCB_SEV_ES_REASON_GENERAL_REQUEST	0
#define		GHCB_SEV_ES_REASON_PROTOCOL_UNSUPPORTED	1

#define	GHCB_SEV_GHCB_RESP_CODE(v)	((v) & 0xfff)
#define	VMGEXIT()			{ asm volatile("rep; vmmcall\n\r"); }

enum es_result {
	ES_OK,			/* All good */
	ES_UNSUPPORTED,		/* Requested operation not supported */
	ES_VMM_ERROR,		/* Unexpected state from the VMM */
	ES_DECODE_FAILED,	/* Instruction decoding failed */
	ES_EXCEPTION,		/* Instruction caused exception */
	ES_RETRY,		/* Retry instruction emulation */
};

struct es_fault_info {
	unsigned long vector;
	unsigned long error_code;
	unsigned long cr2;
};

struct pt_regs;

/* ES instruction emulation context */
struct es_em_ctxt {
	struct pt_regs *regs;
	struct insn insn;
	struct es_fault_info fi;
};

static inline u64 lower_bits(u64 val, unsigned int bits)
{
	u64 mask = (1ULL << bits) - 1;

	return (val & mask);
}

static inline u64 copy_lower_bits(u64 out, u64 in, unsigned int bits)
{
	u64 mask = (1ULL << bits) - 1;

	out &= ~mask;
	out |= lower_bits(in, bits);

	return out;
}

extern void early_vc_handler(void);
extern bool boot_vc_exception(struct pt_regs *regs);

struct real_mode_header;

#ifdef CONFIG_AMD_MEM_ENCRYPT
int sev_es_setup_ap_jump_table(struct real_mode_header *rmh);
void sev_es_nmi_enter(void);
#else /* CONFIG_AMD_MEM_ENCRYPT */
static inline int sev_es_setup_ap_jump_table(struct real_mode_header *rmh)
{
	return 0;
}
static inline void sev_es_nmi_enter(void) { }
#endif /* CONFIG_AMD_MEM_ENCRYPT*/

#else /* !__ASSEMBLY__ */

#ifdef CONFIG_AMD_MEM_ENCRYPT
#define SEV_ES_NMI_COMPLETE		\
	ALTERNATIVE	"", "callq sev_es_nmi_complete", X86_FEATURE_SEV_ES_GUEST

.macro	SEV_ES_IRET_CHECK
	ALTERNATIVE	"jmp	.Lend_\@", "", X86_FEATURE_SEV_ES_GUEST
	movq	PER_CPU_VAR(sev_es_in_nmi), %rdi
	testq	%rdi, %rdi
	jz	.Lend_\@
	callq	sev_es_nmi_complete
.Lend_\@:
.endm

#else  /* CONFIG_AMD_MEM_ENCRYPT */
#define	SEV_ES_NMI_COMPLETE
.macro	SEV_ES_IRET_CHECK
.endm
#endif /* CONFIG_AMD_MEM_ENCRYPT*/

#endif /* __ASSEMBLY__ */

#endif

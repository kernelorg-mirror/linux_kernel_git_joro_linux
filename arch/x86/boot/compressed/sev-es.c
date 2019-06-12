/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include <asm/ptrace.h>
#include <asm/svm.h>
#include "misc.h"
#include "pgtable.h"

#define VMGEXIT()	\
	asm volatile("rep; vmmcall\n\r")

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

#define GHCB_VIRT_ADDR		0xffffffffffe00000UL	/* -2MB */

#define	GHCB_SEV_INFO		0x001UL
#define	GHCB_SEV_INFO_REQ	0x002UL
#define		GHCB_INFO(v)		((v) & 0xfffUL)
#define		GHCB_PROTO_MAX(v)	(((v) >> 48) & 0xffffUL)
#define		GHCB_PROTO_MIN(v)	(((v) >> 32) & 0xffffUL)
#define		GHCB_PROTO_OUR		0x0001UL
#define GHCB_SEV_TERMINATE	0x100UL

extern u64 boot_ghcb_pt_pages;
extern char *boot_ghcb;
struct ghcb *ghcb;

static void terminate(void)
{
	/* Request Guest Termination from Hypvervisor */
	while (true) {
		write_ghcb_msr(GHCB_SEV_TERMINATE);
		VMGEXIT();
	}
}

static void map_ghcb(void)
{
	u64 *l0, *l1, *l2, *l3;
	u64 entry;
	int idx;

	l3 = (u64 *)(__native_read_cr3() & PAGE_MASK);
	l2 = &boot_ghcb_pt_pages;
	l1 = l2 + 512;
	l0 = l1 + 512;

	/* Level 1 */
	idx = PGT_L0_IDX(GHCB_VIRT_ADDR);
	entry = ((u64)&boot_ghcb) | __PAGE_KERNEL;
	l0[idx] = entry;

	/* Level 2 */
	idx = PGT_L1_IDX(GHCB_VIRT_ADDR);
	entry = ((u64)l0) | _PAGE_TABLE;
	l1[idx] = entry;

	/* Level 3 */
	idx = PGT_L2_IDX(GHCB_VIRT_ADDR);
	entry = ((u64)l1) | _PAGE_TABLE;
	l2[idx] = entry;

	/* Level 4 */
	idx = PGT_L3_IDX(GHCB_VIRT_ADDR);
	entry = ((u64)l2) | _PAGE_TABLE;
	l3[idx] = entry;
}

static void clear_ghcb(void)
{
	if (ghcb)
		memset(ghcb, 0, sizeof(*ghcb));
}

static bool setup_ghcb(void)
{
	u64 oldval = read_ghcb_msr();
	u64 val;

	/* Do the GHCB protocol version negotiation */
	write_ghcb_msr(GHCB_SEV_INFO_REQ);
	VMGEXIT();
	val = read_ghcb_msr();

	if (GHCB_INFO(val) != GHCB_SEV_INFO)
		return false;

	if (GHCB_PROTO_OUR > GHCB_PROTO_MAX(val) ||
	    GHCB_PROTO_OUR < GHCB_PROTO_MIN(val))
		return false;

	/* Protocol negotation successful - now map and initialize the GHCB */
	map_ghcb();

	/* GHCB mapped, set pointer and clear area */
	ghcb = (struct ghcb *)GHCB_VIRT_ADDR;
	clear_ghcb();

	return true;
}

void vc_handler(struct pt_regs *regs)
{
	/* Make sure the GHCB is initialized */
	if (ghcb == NULL && !setup_ghcb())
		terminate();

	/* Hang the machine for now */
	while (true)
		asm volatile("hlt\n");
}

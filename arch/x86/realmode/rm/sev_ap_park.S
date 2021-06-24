/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/page_types.h>
#include <asm/processor-flags.h>
#include <asm/msr-index.h>
#include <asm/sev-ap-jumptable.h>
#include "realmode.h"

	.section ".text32", "ax"
	.code32
/*
 * The following code switches to 16-bit protected mode and sets up the
 * execution environment for the AP Jump Table blob. Then it jumps to the AP
 * Jump Table to park the AP.
 *
 * The code was copied from reboot.S and modified to fit the SEV-ES requirements
 * for AP parking. When this code is entered, all registers except %EAX-%EDX are
 * in reset state.
 *
 * The AP Jump Table physical base address is in %EBX upon entry.
 *
 * %EAX, %ECX, %EDX and EFLAGS are undefined. Only use registers %EAX-%EDX and
 * %ESP in this code.
 */
SYM_CODE_START(sev_ap_park_asm)

	/* Switch to trampoline GDT as it is guaranteed < 4 GiB */
	movl	$__KERNEL_DS, %eax
	movl	%eax, %ds
	lgdt	pa_tr_gdt

	/* Disable paging to drop us out of long mode */
	movl	%cr0, %eax
	btcl	$X86_CR0_PG_BIT, %eax
	movl	%eax, %cr0

	ljmpl	$__KERNEL32_CS, $pa_sev_ap_park_paging_off

SYM_INNER_LABEL(sev_ap_park_paging_off, SYM_L_GLOBAL)
	/* Clear EFER */
	movl	$0, %eax
	movl	$0, %edx
	movl	$MSR_EFER, %ecx
	wrmsr

	/* Clear CR3 */
	movl	$0, %ecx
	movl	%ecx, %cr3

	/* Set up the IDT for real mode. */
	lidtl	pa_machine_real_restart_idt

	/*
	 * Load the GDT with the 16-bit segments for the AP Jump Table
	 */
	lgdtl	pa_sev_ap_park_gdt

	/* Setup Code and Data segments for AP Jump Table */
	movw	$SEV_APJT_DS16, %ax
	movw	%ax, %ds
	movw	%ax, %ss

	/* Jump to the AP Jump Table into 16 bit protected mode */
	ljmpw	$SEV_APJT_CS16, $SEV_APJT_ENTRY
SYM_CODE_END(sev_ap_park_asm)

	.data
	.balign	16
SYM_DATA_START(sev_ap_park_gdt)
	/* Self-pointer */
	.word	sev_ap_park_gdt_end - sev_ap_park_gdt - 1
	.long	pa_sev_ap_park_gdt
	.word	0

	/*
	 * Offset 0x8
	 * 32 bit code segment descriptor pointing to AP Jump table base
	 * Setup at runtime in sev_es_setup_ap_jump_table_data().
	 */
	.quad	0

	/*
	 * Offset 0x10
	 * 32 bit data segment descriptor pointing to AP Jump table base
	 * Setup at runtime in sev_es_setup_ap_jump_table_data().
	 */
	.quad	0
SYM_DATA_END_LABEL(sev_ap_park_gdt, SYM_L_GLOBAL, sev_ap_park_gdt_end)

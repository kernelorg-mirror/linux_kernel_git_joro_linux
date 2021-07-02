// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD Memory Encryption Support
 *
 * Copyright (C) 2019 SUSE
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#define pr_fmt(fmt)	"SEV: " fmt

#include <linux/sched/debug.h>	/* For show_regs() */
#include <linux/percpu-defs.h>
#include <linux/mem_encrypt.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/set_memory.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include <asm/sev-ap-jumptable.h>
#include <asm/cpu_entry_area.h>
#include <asm/stacktrace.h>
#include <asm/sev.h>
#include <asm/insn-eval.h>
#include <asm/fpu/internal.h>
#include <asm/processor.h>
#include <asm/realmode.h>
#include <asm/tlbflush.h>
#include <asm/traps.h>
#include <asm/svm.h>
#include <asm/smp.h>
#include <asm/cpu.h>

#define DR7_RESET_VALUE        0x400

/* For early boot hypervisor communication in SEV-ES enabled guests */
static struct ghcb boot_ghcb_page __bss_decrypted __aligned(PAGE_SIZE);

/*
 * Needs to be in the .data section because we need it NULL before bss is
 * cleared
 */
static struct ghcb __initdata *boot_ghcb;

/* Cached AP Jump Table Address */
static phys_addr_t sev_es_jump_table_pa;

/* Whether the AP Jump Table blob was successfully installed */
static bool sev_ap_jumptable_blob_installed __ro_after_init;

/* #VC handler runtime per-CPU data */
struct sev_es_runtime_data {
	struct ghcb ghcb_page;

	/* Physical storage for the per-CPU IST stack of the #VC handler */
	char ist_stack[EXCEPTION_STKSZ] __aligned(PAGE_SIZE);

	/*
	 * Physical storage for the per-CPU fall-back stack of the #VC handler.
	 * The fall-back stack is used when it is not safe to switch back to the
	 * interrupted stack in the #VC entry code.
	 */
	char fallback_stack[EXCEPTION_STKSZ] __aligned(PAGE_SIZE);

	/*
	 * Reserve one page per CPU as backup storage for the unencrypted GHCB.
	 * It is needed when an NMI happens while the #VC handler uses the real
	 * GHCB, and the NMI handler itself is causing another #VC exception. In
	 * that case the GHCB content of the first handler needs to be backed up
	 * and restored.
	 */
	struct ghcb backup_ghcb;

	/*
	 * Mark the per-cpu GHCBs as in-use to detect nested #VC exceptions.
	 * There is no need for it to be atomic, because nothing is written to
	 * the GHCB between the read and the write of ghcb_active. So it is safe
	 * to use it when a nested #VC exception happens before the write.
	 *
	 * This is necessary for example in the #VC->NMI->#VC case when the NMI
	 * happens while the first #VC handler uses the GHCB. When the NMI code
	 * raises a second #VC handler it might overwrite the contents of the
	 * GHCB written by the first handler. To avoid this the content of the
	 * GHCB is saved and restored when the GHCB is detected to be in use
	 * already.
	 */
	bool ghcb_active;
	bool backup_ghcb_active;

	/*
	 * Cached DR7 value - write it on DR7 writes and return it on reads.
	 * That value will never make it to the real hardware DR7 as debugging
	 * is currently unsupported in SEV-ES guests.
	 */
	unsigned long dr7;
};

struct ghcb_state {
	struct ghcb *ghcb;
};

static DEFINE_PER_CPU(struct sev_es_runtime_data*, runtime_data);
DEFINE_STATIC_KEY_FALSE(sev_es_enable_key);

/* Needed in vc_early_forward_exception */
void do_early_exception(struct pt_regs *regs, int trapnr);

static void __init setup_vc_stacks(int cpu)
{
	struct sev_es_runtime_data *data;
	struct cpu_entry_area *cea;
	unsigned long vaddr;
	phys_addr_t pa;

	data = per_cpu(runtime_data, cpu);
	cea  = get_cpu_entry_area(cpu);

	/* Map #VC IST stack */
	vaddr = CEA_ESTACK_BOT(&cea->estacks, VC);
	pa    = __pa(data->ist_stack);
	cea_set_pte((void *)vaddr, pa, PAGE_KERNEL);

	/* Map VC fall-back stack */
	vaddr = CEA_ESTACK_BOT(&cea->estacks, VC2);
	pa    = __pa(data->fallback_stack);
	cea_set_pte((void *)vaddr, pa, PAGE_KERNEL);
}

static __always_inline bool on_vc_stack(struct pt_regs *regs)
{
	unsigned long sp = regs->sp;

	/* User-mode RSP is not trusted */
	if (user_mode(regs))
		return false;

	/* SYSCALL gap still has user-mode RSP */
	if (ip_within_syscall_gap(regs))
		return false;

	return ((sp >= __this_cpu_ist_bottom_va(VC)) && (sp < __this_cpu_ist_top_va(VC)));
}

/*
 * This function handles the case when an NMI is raised in the #VC
 * exception handler entry code, before the #VC handler has switched off
 * its IST stack. In this case, the IST entry for #VC must be adjusted,
 * so that any nested #VC exception will not overwrite the stack
 * contents of the interrupted #VC handler.
 *
 * The IST entry is adjusted unconditionally so that it can be also be
 * unconditionally adjusted back in __sev_es_ist_exit(). Otherwise a
 * nested sev_es_ist_exit() call may adjust back the IST entry too
 * early.
 *
 * The __sev_es_ist_enter() and __sev_es_ist_exit() functions always run
 * on the NMI IST stack, as they are only called from NMI handling code
 * right now.
 */
void noinstr __sev_es_ist_enter(struct pt_regs *regs)
{
	unsigned long old_ist, new_ist;

	/* Read old IST entry */
	new_ist = old_ist = __this_cpu_read(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC]);

	/*
	 * If NMI happened while on the #VC IST stack, set the new IST
	 * value below regs->sp, so that the interrupted stack frame is
	 * not overwritten by subsequent #VC exceptions.
	 */
	if (on_vc_stack(regs))
		new_ist = regs->sp;

	/*
	 * Reserve additional 8 bytes and store old IST value so this
	 * adjustment can be unrolled in __sev_es_ist_exit().
	 */
	new_ist -= sizeof(old_ist);
	*(unsigned long *)new_ist = old_ist;

	/* Set new IST entry */
	this_cpu_write(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC], new_ist);
}

void noinstr __sev_es_ist_exit(void)
{
	unsigned long ist;

	/* Read IST entry */
	ist = __this_cpu_read(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC]);

	if (WARN_ON(ist == __this_cpu_ist_top_va(VC)))
		return;

	/* Read back old IST entry and write it to the TSS */
	this_cpu_write(cpu_tss_rw.x86_tss.ist[IST_INDEX_VC], *(unsigned long *)ist);
}

/*
 * Nothing shall interrupt this code path while holding the per-CPU
 * GHCB. The backup GHCB is only for NMIs interrupting this path.
 *
 * Callers must disable local interrupts around it.
 */
static noinstr struct ghcb *__sev_get_ghcb(struct ghcb_state *state)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	WARN_ON(!irqs_disabled());

	data = this_cpu_read(runtime_data);
	ghcb = &data->ghcb_page;

	if (unlikely(data->ghcb_active)) {
		/* GHCB is already in use - save its contents */

		if (unlikely(data->backup_ghcb_active)) {
			/*
			 * Backup-GHCB is also already in use. There is no way
			 * to continue here so just kill the machine. To make
			 * panic() work, mark GHCBs inactive so that messages
			 * can be printed out.
			 */
			data->ghcb_active        = false;
			data->backup_ghcb_active = false;

			instrumentation_begin();
			panic("Unable to handle #VC exception! GHCB and Backup GHCB are already in use");
			instrumentation_end();
		}

		/* Mark backup_ghcb active before writing to it */
		data->backup_ghcb_active = true;

		state->ghcb = &data->backup_ghcb;

		/* Backup GHCB content */
		*state->ghcb = *ghcb;
	} else {
		state->ghcb = NULL;
		data->ghcb_active = true;
	}

	return ghcb;
}

/* Needed in vc_early_forward_exception */
void do_early_exception(struct pt_regs *regs, int trapnr);

static inline u64 sev_es_rd_ghcb_msr(void)
{
	return __rdmsr(MSR_AMD64_SEV_ES_GHCB);
}

static __always_inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = (u32)(val);
	high = (u32)(val >> 32);

	native_wrmsr(MSR_AMD64_SEV_ES_GHCB, low, high);
}

static int vc_fetch_insn_kernel(struct es_em_ctxt *ctxt,
				unsigned char *buffer)
{
	return copy_from_kernel_nofault(buffer, (unsigned char *)ctxt->regs->ip, MAX_INSN_SIZE);
}

static enum es_result __vc_decode_user_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	int insn_bytes;

	insn_bytes = insn_fetch_from_user_inatomic(ctxt->regs, buffer);
	if (insn_bytes == 0) {
		/* Nothing could be copied */
		ctxt->fi.vector     = X86_TRAP_PF;
		ctxt->fi.error_code = X86_PF_INSTR | X86_PF_USER;
		ctxt->fi.cr2        = ctxt->regs->ip;
		return ES_EXCEPTION;
	} else if (insn_bytes == -EINVAL) {
		/* Effective RIP could not be calculated */
		ctxt->fi.vector     = X86_TRAP_GP;
		ctxt->fi.error_code = 0;
		ctxt->fi.cr2        = 0;
		return ES_EXCEPTION;
	}

	if (!insn_decode_from_regs(&ctxt->insn, ctxt->regs, buffer, insn_bytes))
		return ES_DECODE_FAILED;

	if (ctxt->insn.immediate.got)
		return ES_OK;
	else
		return ES_DECODE_FAILED;
}

static enum es_result __vc_decode_kern_insn(struct es_em_ctxt *ctxt)
{
	char buffer[MAX_INSN_SIZE];
	int res, ret;

	res = vc_fetch_insn_kernel(ctxt, buffer);
	if (res) {
		ctxt->fi.vector     = X86_TRAP_PF;
		ctxt->fi.error_code = X86_PF_INSTR;
		ctxt->fi.cr2        = ctxt->regs->ip;
		return ES_EXCEPTION;
	}

	ret = insn_decode(&ctxt->insn, buffer, MAX_INSN_SIZE, INSN_MODE_64);
	if (ret < 0)
		return ES_DECODE_FAILED;
	else
		return ES_OK;
}

static enum es_result vc_decode_insn(struct es_em_ctxt *ctxt)
{
	if (user_mode(ctxt->regs))
		return __vc_decode_user_insn(ctxt);
	else
		return __vc_decode_kern_insn(ctxt);
}

static enum es_result vc_write_mem(struct es_em_ctxt *ctxt,
				   char *dst, char *buf, size_t size)
{
	unsigned long error_code = X86_PF_PROT | X86_PF_WRITE;
	char __user *target = (char __user *)dst;
	u64 d8;
	u32 d4;
	u16 d2;
	u8  d1;

	/*
	 * This function uses __put_user() independent of whether kernel or user
	 * memory is accessed. This works fine because __put_user() does no
	 * sanity checks of the pointer being accessed. All that it does is
	 * to report when the access failed.
	 *
	 * Also, this function runs in atomic context, so __put_user() is not
	 * allowed to sleep. The page-fault handler detects that it is running
	 * in atomic context and will not try to take mmap_sem and handle the
	 * fault, so additional pagefault_enable()/disable() calls are not
	 * needed.
	 *
	 * The access can't be done via copy_to_user() here because
	 * vc_write_mem() must not use string instructions to access unsafe
	 * memory. The reason is that MOVS is emulated by the #VC handler by
	 * splitting the move up into a read and a write and taking a nested #VC
	 * exception on whatever of them is the MMIO access. Using string
	 * instructions here would cause infinite nesting.
	 */
	switch (size) {
	case 1:
		memcpy(&d1, buf, 1);
		if (__put_user(d1, target))
			goto fault;
		break;
	case 2:
		memcpy(&d2, buf, 2);
		if (__put_user(d2, target))
			goto fault;
		break;
	case 4:
		memcpy(&d4, buf, 4);
		if (__put_user(d4, target))
			goto fault;
		break;
	case 8:
		memcpy(&d8, buf, 8);
		if (__put_user(d8, target))
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
	char __user *s = (char __user *)src;
	u64 d8;
	u32 d4;
	u16 d2;
	u8  d1;

	/*
	 * This function uses __get_user() independent of whether kernel or user
	 * memory is accessed. This works fine because __get_user() does no
	 * sanity checks of the pointer being accessed. All that it does is
	 * to report when the access failed.
	 *
	 * Also, this function runs in atomic context, so __get_user() is not
	 * allowed to sleep. The page-fault handler detects that it is running
	 * in atomic context and will not try to take mmap_sem and handle the
	 * fault, so additional pagefault_enable()/disable() calls are not
	 * needed.
	 *
	 * The access can't be done via copy_from_user() here because
	 * vc_read_mem() must not use string instructions to access unsafe
	 * memory. The reason is that MOVS is emulated by the #VC handler by
	 * splitting the move up into a read and a write and taking a nested #VC
	 * exception on whatever of them is the MMIO access. Using string
	 * instructions here would cause infinite nesting.
	 */
	switch (size) {
	case 1:
		if (__get_user(d1, s))
			goto fault;
		memcpy(buf, &d1, 1);
		break;
	case 2:
		if (__get_user(d2, s))
			goto fault;
		memcpy(buf, &d2, 2);
		break;
	case 4:
		if (__get_user(d4, s))
			goto fault;
		memcpy(buf, &d4, 4);
		break;
	case 8:
		if (__get_user(d8, s))
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

static enum es_result vc_slow_virt_to_phys(struct ghcb *ghcb, struct es_em_ctxt *ctxt,
					   unsigned long vaddr, phys_addr_t *paddr)
{
	unsigned long va = (unsigned long)vaddr;
	unsigned int level;
	phys_addr_t pa;
	pgd_t *pgd;
	pte_t *pte;

	pgd = __va(read_cr3_pa());
	pgd = &pgd[pgd_index(va)];
	pte = lookup_address_in_pgd(pgd, va, &level);
	if (!pte) {
		ctxt->fi.vector     = X86_TRAP_PF;
		ctxt->fi.cr2        = vaddr;
		ctxt->fi.error_code = 0;

		if (user_mode(ctxt->regs))
			ctxt->fi.error_code |= X86_PF_USER;

		return ES_EXCEPTION;
	}

	if (WARN_ON_ONCE(pte_val(*pte) & _PAGE_ENC))
		/* Emulated MMIO to/from encrypted memory not supported */
		return ES_UNSUPPORTED;

	pa = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
	pa |= va & ~page_level_mask(level);

	*paddr = pa;

	return ES_OK;
}

/* Include code shared with pre-decompression boot stage */
#include "sev-shared.c"

/* Negotiated GHCB protocol version */
static struct sev_ghcb_protocol_info ghcb_protocol_info __ro_after_init;

static u64 sev_get_ghcb_proto_ver(void)
{
	return ghcb_protocol_info.vm_proto;
}

static noinstr void __sev_put_ghcb(struct ghcb_state *state)
{
	struct sev_es_runtime_data *data;
	struct ghcb *ghcb;

	WARN_ON(!irqs_disabled());

	data = this_cpu_read(runtime_data);
	ghcb = &data->ghcb_page;

	if (state->ghcb) {
		/* Restore GHCB from Backup */
		*ghcb = *state->ghcb;
		data->backup_ghcb_active = false;
		state->ghcb = NULL;
	} else {
		/*
		 * Invalidate the GHCB so a VMGEXIT instruction issued
		 * from userspace won't appear to be valid.
		 */
		vc_ghcb_invalidate(ghcb);
		data->ghcb_active = false;
	}
}

void noinstr __sev_es_nmi_complete(void)
{
	struct ghcb_state state;
	struct ghcb *ghcb;

	ghcb = __sev_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_NMI_COMPLETE);
	ghcb_set_sw_exit_info_1(ghcb, 0);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	sev_es_wr_ghcb_msr(__pa_nodebug(ghcb));
	VMGEXIT();

	__sev_put_ghcb(&state);
}

static phys_addr_t get_jump_table_addr(void)
{
	struct ghcb_state state;
	unsigned long flags;
	struct ghcb *ghcb;

	if (sev_es_jump_table_pa)
		return sev_es_jump_table_pa;

	local_irq_save(flags);

	ghcb = __sev_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_JUMP_TABLE);
	ghcb_set_sw_exit_info_1(ghcb, SVM_VMGEXIT_GET_AP_JUMP_TABLE);
	ghcb_set_sw_exit_info_2(ghcb, 0);

	sev_es_wr_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	if (ghcb_sw_exit_info_1_is_valid(ghcb) &&
	    ghcb_sw_exit_info_2_is_valid(ghcb))
		sev_es_jump_table_pa = (phys_addr_t)ghcb->save.sw_exit_info_2;

	__sev_put_ghcb(&state);

	local_irq_restore(flags);

	return sev_es_jump_table_pa;
}

int sev_es_setup_ap_jump_table(struct real_mode_header *rmh)
{
	u16 startup_cs, startup_ip;
	u16 __iomem *jump_table;
	phys_addr_t pa;

	pa = get_jump_table_addr();

	/* On UP guests there is no jump table so this is not a failure */
	if (!pa)
		return 0;

	/* Check if AP Jump Table is page-aligned */
	if (pa & ~PAGE_MASK)
		return -EINVAL;

	startup_cs = (u16)(rmh->trampoline_start >> 4);
	startup_ip = (u16)(rmh->sev_es_trampoline_start -
			   rmh->trampoline_start);

	jump_table = ioremap_encrypted(pa, PAGE_SIZE);
	if (!jump_table)
		return -EIO;

	writew(startup_ip, &jump_table[0]);
	writew(startup_cs, &jump_table[1]);

	iounmap(jump_table);

	return 0;
}

/*
 * This is needed by the OVMF UEFI firmware which will use whatever it finds in
 * the GHCB MSR as its GHCB to talk to the hypervisor. So make sure the per-cpu
 * runtime GHCBs used by the kernel are also mapped in the EFI page-table.
 */
int __init sev_es_efi_map_ghcbs(pgd_t *pgd)
{
	struct sev_es_runtime_data *data;
	unsigned long address, pflags;
	int cpu;
	u64 pfn;

	if (!sev_es_active())
		return 0;

	pflags = _PAGE_NX | _PAGE_RW;

	for_each_possible_cpu(cpu) {
		data = per_cpu(runtime_data, cpu);

		address = __pa(&data->ghcb_page);
		pfn = address >> PAGE_SHIFT;

		if (kernel_map_pages_in_pgd(pgd, pfn, address, 1, pflags))
			return 1;
	}

	return 0;
}

static enum es_result vc_handle_msr(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	struct pt_regs *regs = ctxt->regs;
	enum es_result ret;
	u64 exit_info_1;

	/* Is it a WRMSR? */
	exit_info_1 = (ctxt->insn.opcode.bytes[1] == 0x30) ? 1 : 0;

	ghcb_set_rcx(ghcb, regs->cx);
	if (exit_info_1) {
		ghcb_set_rax(ghcb, regs->ax);
		ghcb_set_rdx(ghcb, regs->dx);
	}

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_MSR, exit_info_1, 0);

	if ((ret == ES_OK) && (!exit_info_1)) {
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
	if (!sev_es_negotiate_protocol(&ghcb_protocol_info))
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

void __noreturn sev_jumptable_ap_park(void)
{
	local_irq_disable();

	write_cr3(real_mode_header->trampoline_pgd);

	/* Exiting long mode will fail if CR4.PCIDE is set. */
	if (boot_cpu_has(X86_FEATURE_PCID))
		cr4_clear_bits(X86_CR4_PCIDE);

	asm volatile("xorq	%%r15, %%r15\n"
		     "xorq	%%r14, %%r14\n"
		     "xorq	%%r13, %%r13\n"
		     "xorq	%%r12, %%r12\n"
		     "xorq	%%r11, %%r11\n"
		     "xorq	%%r10, %%r10\n"
		     "xorq	%%r9,  %%r9\n"
		     "xorq	%%r8,  %%r8\n"
		     "xorq	%%rsi, %%rsi\n"
		     "xorq	%%rdi, %%rdi\n"
		     "xorq	%%rsp, %%rsp\n"
		     "xorq	%%rbp, %%rbp\n"
		     "ljmpl	*%0" : :
		     "m" (real_mode_header->sev_real_ap_park_asm),
		     "b" (sev_es_jump_table_pa >> 4));
	unreachable();
}
STACK_FRAME_NON_STANDARD(sev_jumptable_ap_park);

void __sev_es_stop_this_cpu(void)
{
	/* Only park in the AP Jump Table when the code has been installed */
	if (!sev_ap_jumptable_blob_installed)
		return;

	sev_jumptable_ap_park();
}

#ifdef CONFIG_HOTPLUG_CPU
static void sev_es_ap_hlt_loop(void)
{
	struct ghcb_state state;
	struct ghcb *ghcb;

	ghcb = __sev_get_ghcb(&state);

	while (true) {
		vc_ghcb_invalidate(ghcb);
		ghcb_set_sw_exit_code(ghcb, SVM_VMGEXIT_AP_HLT_LOOP);
		ghcb_set_sw_exit_info_1(ghcb, 0);
		ghcb_set_sw_exit_info_2(ghcb, 0);

		sev_es_wr_ghcb_msr(__pa(ghcb));
		VMGEXIT();

		/* Wakeup signal? */
		if (ghcb_sw_exit_info_2_is_valid(ghcb) &&
		    ghcb->save.sw_exit_info_2)
			break;
	}

	__sev_put_ghcb(&state);
}

/*
 * Play_dead handler when running under SEV-ES. This is needed because
 * the hypervisor can't deliver an SIPI request to restart the AP.
 * Instead the kernel has to issue a VMGEXIT to halt the VCPU until the
 * hypervisor wakes it up again.
 */
static void sev_es_play_dead(void)
{
	play_dead_common();

	/* IRQs now disabled */
	if (sev_ap_jumptable_blob_installed)
		sev_jumptable_ap_park();
	else
		sev_es_ap_hlt_loop();

	/*
	 * If we get here, the VCPU was woken up again. Jump to CPU
	 * startup code to get it back online.
	 */
	start_cpu0();
}
#else  /* CONFIG_HOTPLUG_CPU */
#define sev_es_play_dead	native_play_dead
#endif /* CONFIG_HOTPLUG_CPU */

#ifdef CONFIG_SMP
static void __init sev_es_setup_play_dead(void)
{
	smp_ops.play_dead = sev_es_play_dead;
}
#else
static inline void sev_es_setup_play_dead(void) { }
#endif

/*
 * This function make the necessary runtime changes to the AP Jump Table blob.
 * For now this only sets up the GDT used while the code executes. The GDT needs
 * to contain 16-bit code and data segments with a base that points to AP Jump
 * Table page.
 */
void __init sev_es_setup_ap_jump_table_data(void *base, u32 pa)
{
	struct sev_ap_jump_table_header *header;
	u64 *ap_jumptable_gdt, *sev_ap_park_gdt;
	struct desc_ptr *gdt_descr;
	int idx;

	header = base;

	/*
	 * Setup 16-bit protected mode code and data segments for AP Jumptable.
	 * Set the segment limits to 0xffff to already be compatible with
	 * real-mode.
	 */
	ap_jumptable_gdt = (u64 *)(base + header->gdt_offset);
	sev_ap_park_gdt  = __va(real_mode_header->sev_ap_park_gdt);

	idx = SEV_APJT_CS16 / 8;
	ap_jumptable_gdt[idx] = sev_ap_park_gdt[idx] = GDT_ENTRY(0x9b, pa, 0xffff);

	idx = SEV_APJT_DS16 / 8;
	ap_jumptable_gdt[idx] = sev_ap_park_gdt[idx] = GDT_ENTRY(0x93, pa, 0xffff);

	/* Write correct GDT base address into GDT descriptor */
	gdt_descr = (struct desc_ptr *)(base + header->gdt_offset);
	gdt_descr->address += pa;
}

/*
 * This function sets up the AP Jump Table blob which contains code which runs
 * in 16-bit protected mode to park an AP. After the AP is woken up again the
 * code will disable protected mode and jump to the reset vector which is also
 * stored in the AP Jump Table.
 *
 * The Jump Table is a safe place to park an AP, because it is owned by the
 * BIOS and writable by the OS. Putting the code in kernel memory would break
 * with kexec, because by the time th APs wake up the memory is owned by
 * the new kernel, and possibly already overwritten.
 *
 * Kexec is also the reason this function is called as an init-call after SMP
 * bringup. Only after all CPUs are up there is a guarantee that no AP is still
 * parked in AP jump-table code.
 */
static int __init sev_es_setup_ap_jump_table_blob(void)
{
	size_t blob_size = rm_ap_jump_table_blob_end - rm_ap_jump_table_blob;
	u16 startup_cs, startup_ip;
	u16 __iomem *jump_table;
	phys_addr_t pa;

	if (!sev_es_active())
		return 0;

	if (sev_get_ghcb_proto_ver() < 2) {
		pr_info("AP Jump Table parking requires at least GHCB protocol version 2\n");
		return 0;
	}

	pa = get_jump_table_addr();

	/* Overflow and size checks for untrusted Jump Table address */
	if (pa + PAGE_SIZE < pa || pa + PAGE_SIZE > SZ_4G) {
		pr_info("AP Jump Table is above 4GB - not enabling AP Jump Table parking\n");
		return 0;
	}

	/* On UP guests there is no jump table so this is not a failure */
	if (!pa)
		return 0;

	jump_table = ioremap_encrypted(pa, PAGE_SIZE);
	if (WARN_ON(!jump_table))
		return -EINVAL;

	/*
	 * Safe reset vector to restore it later because the blob will
	 * overwrite it.
	 */
	startup_ip = jump_table[0];
	startup_cs = jump_table[1];

	/* Install AP Jump Table Blob with real mode AP parking code */
	memcpy_toio(jump_table, rm_ap_jump_table_blob, blob_size);

	/* Setup AP Jumptable GDT */
	sev_es_setup_ap_jump_table_data(jump_table, (u32)pa);

	writew(startup_ip, &jump_table[0]);
	writew(startup_cs, &jump_table[1]);

	iounmap(jump_table);

	pr_info("AP Jump Table Blob successfully set up\n");

	/* Mark AP Jump Table blob as available */
	sev_ap_jumptable_blob_installed = true;

	return 0;
}
core_initcall(sev_es_setup_ap_jump_table_blob);

bool sev_kexec_supported(void)
{
	/*
	 * KEXEC with SEV-ES and more than one CPU is only supported
	 * when the AP Jump Table is installed.
	 */
	if (num_possible_cpus() > 1)
		return !sev_es_active() || sev_ap_jumptable_blob_installed;
	else
		return true;
}

static void __init alloc_runtime_data(int cpu)
{
	struct sev_es_runtime_data *data;

	data = memblock_alloc(sizeof(*data), PAGE_SIZE);
	if (!data)
		panic("Can't allocate SEV-ES runtime data");

	per_cpu(runtime_data, cpu) = data;
}

static void __init init_ghcb(int cpu)
{
	struct sev_es_runtime_data *data;
	int err;

	data = per_cpu(runtime_data, cpu);

	err = early_set_memory_decrypted((unsigned long)&data->ghcb_page,
					 sizeof(data->ghcb_page));
	if (err)
		panic("Can't map GHCBs unencrypted");

	memset(&data->ghcb_page, 0, sizeof(data->ghcb_page));

	data->ghcb_active = false;
	data->backup_ghcb_active = false;
}

void __init sev_es_init_vc_handling(void)
{
	int cpu;

	BUILD_BUG_ON(offsetof(struct sev_es_runtime_data, ghcb_page) % PAGE_SIZE);

	if (!sev_es_active())
		return;

	if (!sev_es_check_cpu_features())
		panic("SEV-ES CPU Features missing");

	/* Enable SEV-ES special handling */
	static_branch_enable(&sev_es_enable_key);

	/* Initialize per-cpu GHCB pages */
	for_each_possible_cpu(cpu) {
		alloc_runtime_data(cpu);
		init_ghcb(cpu);
		setup_vc_stacks(cpu);
	}

	sev_es_setup_play_dead();

	/* Secondary CPUs use the runtime #VC handler */
	initial_vc_handler = (unsigned long)kernel_exc_vmm_communication;

	/*
	 * Print information about supported and negotiated GHCB protocol
	 * versions.
	 */
	pr_info("Hypervisor GHCB protocol version support: min=%u max=%u\n",
		ghcb_protocol_info.hv_proto_min, ghcb_protocol_info.hv_proto_max);
	pr_info("Using GHCB protocol version %u\n", ghcb_protocol_info.vm_proto);
}

static void __init vc_early_forward_exception(struct es_em_ctxt *ctxt)
{
	int trapnr = ctxt->fi.vector;

	if (trapnr == X86_TRAP_PF)
		native_write_cr2(ctxt->fi.cr2);

	ctxt->regs->orig_ax = ctxt->fi.error_code;
	do_early_exception(ctxt->regs, trapnr);
}

static enum es_result vc_handle_dr7_write(struct ghcb *ghcb,
					  struct es_em_ctxt *ctxt)
{
	struct sev_es_runtime_data *data = this_cpu_read(runtime_data);
	long val, *reg = vc_insn_get_rm(ctxt);
	enum es_result ret;

	if (!reg)
		return ES_DECODE_FAILED;

	val = *reg;

	/* Upper 32 bits must be written as zeroes */
	if (val >> 32) {
		ctxt->fi.vector = X86_TRAP_GP;
		ctxt->fi.error_code = 0;
		return ES_EXCEPTION;
	}

	/* Clear out other reserved bits and set bit 10 */
	val = (val & 0xffff23ffL) | BIT(10);

	/* Early non-zero writes to DR7 are not supported */
	if (!data && (val & ~DR7_RESET_VALUE))
		return ES_UNSUPPORTED;

	/* Using a value of 0 for ExitInfo1 means RAX holds the value */
	ghcb_set_rax(ghcb, val);
	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_WRITE_DR7, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (data)
		data->dr7 = val;

	return ES_OK;
}

static enum es_result vc_handle_dr7_read(struct ghcb *ghcb,
					 struct es_em_ctxt *ctxt)
{
	struct sev_es_runtime_data *data = this_cpu_read(runtime_data);
	long *reg = vc_insn_get_rm(ctxt);

	if (!reg)
		return ES_DECODE_FAILED;

	if (data)
		*reg = data->dr7;
	else
		*reg = DR7_RESET_VALUE;

	return ES_OK;
}

static enum es_result vc_handle_wbinvd(struct ghcb *ghcb,
				       struct es_em_ctxt *ctxt)
{
	return sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_WBINVD, 0, 0);
}

static enum es_result vc_handle_rdpmc(struct ghcb *ghcb, struct es_em_ctxt *ctxt)
{
	enum es_result ret;

	ghcb_set_rcx(ghcb, ctxt->regs->cx);

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_RDPMC, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!(ghcb_rax_is_valid(ghcb) && ghcb_rdx_is_valid(ghcb)))
		return ES_VMM_ERROR;

	ctxt->regs->ax = ghcb->save.rax;
	ctxt->regs->dx = ghcb->save.rdx;

	return ES_OK;
}

static enum es_result vc_handle_monitor(struct ghcb *ghcb,
					struct es_em_ctxt *ctxt)
{
	/*
	 * Treat it as a NOP and do not leak a physical address to the
	 * hypervisor.
	 */
	return ES_OK;
}

static enum es_result vc_handle_mwait(struct ghcb *ghcb,
				      struct es_em_ctxt *ctxt)
{
	/* Treat the same as MONITOR/MONITORX */
	return ES_OK;
}

static enum es_result vc_handle_vmmcall(struct ghcb *ghcb,
					struct es_em_ctxt *ctxt)
{
	enum es_result ret;

	ghcb_set_rax(ghcb, ctxt->regs->ax);
	ghcb_set_cpl(ghcb, user_mode(ctxt->regs) ? 3 : 0);

	if (x86_platform.hyper.sev_es_hcall_prepare)
		x86_platform.hyper.sev_es_hcall_prepare(ghcb, ctxt->regs);

	ret = sev_es_ghcb_hv_call(ghcb, ctxt, SVM_EXIT_VMMCALL, 0, 0);
	if (ret != ES_OK)
		return ret;

	if (!ghcb_rax_is_valid(ghcb))
		return ES_VMM_ERROR;

	ctxt->regs->ax = ghcb->save.rax;

	/*
	 * Call sev_es_hcall_finish() after regs->ax is already set.
	 * This allows the hypervisor handler to overwrite it again if
	 * necessary.
	 */
	if (x86_platform.hyper.sev_es_hcall_finish &&
	    !x86_platform.hyper.sev_es_hcall_finish(ghcb, ctxt->regs))
		return ES_VMM_ERROR;

	return ES_OK;
}

static enum es_result vc_handle_trap_ac(struct ghcb *ghcb,
					struct es_em_ctxt *ctxt)
{
	/*
	 * Calling ecx_alignment_check() directly does not work, because it
	 * enables IRQs and the GHCB is active. Forward the exception and call
	 * it later from vc_forward_exception().
	 */
	ctxt->fi.vector = X86_TRAP_AC;
	ctxt->fi.error_code = 0;
	return ES_EXCEPTION;
}

static enum es_result vc_handle_exitcode(struct es_em_ctxt *ctxt,
					 struct ghcb *ghcb,
					 unsigned long exit_code)
{
	enum es_result result;

	switch (exit_code) {
	case SVM_EXIT_READ_DR7:
		result = vc_handle_dr7_read(ghcb, ctxt);
		break;
	case SVM_EXIT_WRITE_DR7:
		result = vc_handle_dr7_write(ghcb, ctxt);
		break;
	case SVM_EXIT_EXCP_BASE + X86_TRAP_AC:
		result = vc_handle_trap_ac(ghcb, ctxt);
		break;
	case SVM_EXIT_RDTSC:
	case SVM_EXIT_RDTSCP:
		result = vc_handle_rdtsc(ghcb, ctxt, exit_code);
		break;
	case SVM_EXIT_RDPMC:
		result = vc_handle_rdpmc(ghcb, ctxt);
		break;
	case SVM_EXIT_INVD:
		pr_err_ratelimited("#VC exception for INVD??? Seriously???\n");
		result = ES_UNSUPPORTED;
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
	case SVM_EXIT_VMMCALL:
		result = vc_handle_vmmcall(ghcb, ctxt);
		break;
	case SVM_EXIT_WBINVD:
		result = vc_handle_wbinvd(ghcb, ctxt);
		break;
	case SVM_EXIT_MONITOR:
		result = vc_handle_monitor(ghcb, ctxt);
		break;
	case SVM_EXIT_MWAIT:
		result = vc_handle_mwait(ghcb, ctxt);
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

static __always_inline void vc_forward_exception(struct es_em_ctxt *ctxt)
{
	long error_code = ctxt->fi.error_code;
	int trapnr = ctxt->fi.vector;

	ctxt->regs->orig_ax = ctxt->fi.error_code;

	switch (trapnr) {
	case X86_TRAP_GP:
		exc_general_protection(ctxt->regs, error_code);
		break;
	case X86_TRAP_UD:
		exc_invalid_op(ctxt->regs);
		break;
	case X86_TRAP_PF:
		write_cr2(ctxt->fi.cr2);
		exc_page_fault(ctxt->regs, error_code);
		break;
	case X86_TRAP_AC:
		exc_alignment_check(ctxt->regs, error_code);
		break;
	default:
		pr_emerg("Unsupported exception in #VC instruction emulation - can't continue\n");
		BUG();
	}
}

static __always_inline bool on_vc_fallback_stack(struct pt_regs *regs)
{
	unsigned long sp = (unsigned long)regs;

	return (sp >= __this_cpu_ist_bottom_va(VC2) && sp < __this_cpu_ist_top_va(VC2));
}

static bool vc_raw_handle_exception(struct pt_regs *regs, unsigned long error_code)
{
	struct ghcb_state state;
	struct es_em_ctxt ctxt;
	enum es_result result;
	struct ghcb *ghcb;
	bool ret = true;

	ghcb = __sev_get_ghcb(&state);

	vc_ghcb_invalidate(ghcb);
	result = vc_init_em_ctxt(&ctxt, regs, error_code);

	if (result == ES_OK)
		result = vc_handle_exitcode(&ctxt, ghcb, error_code);

	__sev_put_ghcb(&state);

	/* Done - now check the result */
	switch (result) {
	case ES_OK:
		vc_finish_insn(&ctxt);
		break;
	case ES_UNSUPPORTED:
		pr_err_ratelimited("Unsupported exit-code 0x%02lx in #VC exception (IP: 0x%lx)\n",
				   error_code, regs->ip);
		ret = false;
		break;
	case ES_VMM_ERROR:
		pr_err_ratelimited("Failure in communication with VMM (exit-code 0x%02lx IP: 0x%lx)\n",
				   error_code, regs->ip);
		ret = false;
		break;
	case ES_DECODE_FAILED:
		pr_err_ratelimited("Failed to decode instruction (exit-code 0x%02lx IP: 0x%lx)\n",
				   error_code, regs->ip);
		ret = false;
		break;
	case ES_EXCEPTION:
		vc_forward_exception(&ctxt);
		break;
	case ES_RETRY:
		/* Nothing to do */
		break;
	default:
		pr_emerg("Unknown result in %s():%d\n", __func__, result);
		/*
		 * Emulating the instruction which caused the #VC exception
		 * failed - can't continue so print debug information
		 */
		BUG();
	}

	return ret;
}

static __always_inline bool vc_is_db(unsigned long error_code)
{
	return error_code == SVM_EXIT_EXCP_BASE + X86_TRAP_DB;
}

/*
 * Runtime #VC exception handler when raised from kernel mode. Runs in NMI mode
 * and will panic when an error happens.
 */
DEFINE_IDTENTRY_VC_KERNEL(exc_vmm_communication)
{
	irqentry_state_t irq_state;

	/*
	 * With the current implementation it is always possible to switch to a
	 * safe stack because #VC exceptions only happen at known places, like
	 * intercepted instructions or accesses to MMIO areas/IO ports. They can
	 * also happen with code instrumentation when the hypervisor intercepts
	 * #DB, but the critical paths are forbidden to be instrumented, so #DB
	 * exceptions currently also only happen in safe places.
	 *
	 * But keep this here in case the noinstr annotations are violated due
	 * to bug elsewhere.
	 */
	if (unlikely(on_vc_fallback_stack(regs))) {
		instrumentation_begin();
		panic("Can't handle #VC exception from unsupported context\n");
		instrumentation_end();
	}

	/*
	 * Handle #DB before calling into !noinstr code to avoid recursive #DB.
	 */
	if (vc_is_db(error_code)) {
		exc_debug(regs);
		return;
	}

	irq_state = irqentry_nmi_enter(regs);

	instrumentation_begin();

	if (!vc_raw_handle_exception(regs, error_code)) {
		/* Show some debug info */
		show_regs(regs);

		/* Ask hypervisor to sev_es_terminate */
		sev_es_terminate(GHCB_SEV_ES_REASON_GENERAL_REQUEST);

		/* If that fails and we get here - just panic */
		panic("Returned from Terminate-Request to Hypervisor\n");
	}

	instrumentation_end();
	irqentry_nmi_exit(regs, irq_state);
}

/*
 * Runtime #VC exception handler when raised from user mode. Runs in IRQ mode
 * and will kill the current task with SIGBUS when an error happens.
 */
DEFINE_IDTENTRY_VC_USER(exc_vmm_communication)
{
	/*
	 * Handle #DB before calling into !noinstr code to avoid recursive #DB.
	 */
	if (vc_is_db(error_code)) {
		noist_exc_debug(regs);
		return;
	}

	irqentry_enter_from_user_mode(regs);
	instrumentation_begin();

	if (!vc_raw_handle_exception(regs, error_code)) {
		/*
		 * Do not kill the machine if user-space triggered the
		 * exception. Send SIGBUS instead and let user-space deal with
		 * it.
		 */
		force_sig_fault(SIGBUS, BUS_OBJERR, (void __user *)0);
	}

	instrumentation_end();
	irqentry_exit_to_user_mode(regs);
}

bool __init handle_vc_boot_ghcb(struct pt_regs *regs)
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
		vc_early_forward_exception(&ctxt);
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

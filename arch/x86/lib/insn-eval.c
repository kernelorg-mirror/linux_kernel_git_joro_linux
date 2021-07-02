/*
 * Utility functions for x86 operand and address decoding
 *
 * Copyright (C) Intel Corporation 2017
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ratelimit.h>
#include <linux/mmu_context.h>
#include <asm/desc_defs.h>
#include <asm/desc.h>
#include <asm/inat.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/ldt.h>
#include <asm/vm86.h>

#undef pr_fmt
#define pr_fmt(fmt) "insn: " fmt

static int get_seg_base_limit(struct insn *insn, struct pt_regs *regs,
			      int regoff, unsigned long *base,
			      unsigned long *limit);

#include "insn-eval-shared.c"

/**
 * get_seg_reg_override_idx() - obtain segment register override index
 * @insn:	Valid instruction with segment override prefixes
 *
 * Inspect the instruction prefixes in @insn and find segment overrides, if any.
 *
 * Returns:
 *
 * A constant identifying the segment register to use, among CS, SS, DS,
 * ES, FS, or GS. INAT_SEG_REG_DEFAULT is returned if no segment override
 * prefixes were found.
 *
 * -EINVAL in case of error.
 */
static int get_seg_reg_override_idx(struct insn *insn)
{
	int idx = INAT_SEG_REG_DEFAULT;
	int num_overrides = 0, i;
	insn_byte_t p;

	insn_get_prefixes(insn);

	/* Look for any segment override prefixes. */
	for_each_insn_prefix(insn, i, p) {
		insn_attr_t attr;

		attr = inat_get_opcode_attribute(p);
		switch (attr) {
		case INAT_MAKE_PREFIX(INAT_PFX_CS):
			idx = INAT_SEG_REG_CS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_SS):
			idx = INAT_SEG_REG_SS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_DS):
			idx = INAT_SEG_REG_DS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_ES):
			idx = INAT_SEG_REG_ES;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_FS):
			idx = INAT_SEG_REG_FS;
			num_overrides++;
			break;
		case INAT_MAKE_PREFIX(INAT_PFX_GS):
			idx = INAT_SEG_REG_GS;
			num_overrides++;
			break;
		/* No default action needed. */
		}
	}

	/* More than one segment override prefix leads to undefined behavior. */
	if (num_overrides > 1)
		return -EINVAL;

	return idx;
}

/**
 * check_seg_overrides() - check if segment override prefixes are allowed
 * @insn:	Valid instruction with segment override prefixes
 * @regoff:	Operand offset, in pt_regs, for which the check is performed
 *
 * For a particular register used in register-indirect addressing, determine if
 * segment override prefixes can be used. Specifically, no overrides are allowed
 * for rDI if used with a string instruction.
 *
 * Returns:
 *
 * True if segment override prefixes can be used with the register indicated
 * in @regoff. False if otherwise.
 */
static bool check_seg_overrides(struct insn *insn, int regoff)
{
	if (regoff == offsetof(struct pt_regs, di) && is_string_insn(insn))
		return false;

	return true;
}

/**
 * resolve_default_seg() - resolve default segment register index for an operand
 * @insn:	Instruction with opcode and address size. Must be valid.
 * @regs:	Register values as seen when entering kernel mode
 * @off:	Operand offset, in pt_regs, for which resolution is needed
 *
 * Resolve the default segment register index associated with the instruction
 * operand register indicated by @off. Such index is resolved based on defaults
 * described in the Intel Software Development Manual.
 *
 * Returns:
 *
 * If in protected mode, a constant identifying the segment register to use,
 * among CS, SS, ES or DS. If in long mode, INAT_SEG_REG_IGNORE.
 *
 * -EINVAL in case of error.
 */
static int resolve_default_seg(struct insn *insn, struct pt_regs *regs, int off)
{
	if (any_64bit_mode(regs))
		return INAT_SEG_REG_IGNORE;
	/*
	 * Resolve the default segment register as described in Section 3.7.4
	 * of the Intel Software Development Manual Vol. 1:
	 *
	 *  + DS for all references involving r[ABCD]X, and rSI.
	 *  + If used in a string instruction, ES for rDI. Otherwise, DS.
	 *  + AX, CX and DX are not valid register operands in 16-bit address
	 *    encodings but are valid for 32-bit and 64-bit encodings.
	 *  + -EDOM is reserved to identify for cases in which no register
	 *    is used (i.e., displacement-only addressing). Use DS.
	 *  + SS for rSP or rBP.
	 *  + CS for rIP.
	 */

	switch (off) {
	case offsetof(struct pt_regs, ax):
	case offsetof(struct pt_regs, cx):
	case offsetof(struct pt_regs, dx):
		/* Need insn to verify address size. */
		if (insn->addr_bytes == 2)
			return -EINVAL;

		fallthrough;

	case -EDOM:
	case offsetof(struct pt_regs, bx):
	case offsetof(struct pt_regs, si):
		return INAT_SEG_REG_DS;

	case offsetof(struct pt_regs, di):
		if (is_string_insn(insn))
			return INAT_SEG_REG_ES;
		return INAT_SEG_REG_DS;

	case offsetof(struct pt_regs, bp):
	case offsetof(struct pt_regs, sp):
		return INAT_SEG_REG_SS;

	case offsetof(struct pt_regs, ip):
		return INAT_SEG_REG_CS;

	default:
		return -EINVAL;
	}
}

/**
 * resolve_seg_reg() - obtain segment register index
 * @insn:	Instruction with operands
 * @regs:	Register values as seen when entering kernel mode
 * @regoff:	Operand offset, in pt_regs, used to determine segment register
 *
 * Determine the segment register associated with the operands and, if
 * applicable, prefixes and the instruction pointed by @insn.
 *
 * The segment register associated to an operand used in register-indirect
 * addressing depends on:
 *
 * a) Whether running in long mode (in such a case segments are ignored, except
 * if FS or GS are used).
 *
 * b) Whether segment override prefixes can be used. Certain instructions and
 *    registers do not allow override prefixes.
 *
 * c) Whether segment overrides prefixes are found in the instruction prefixes.
 *
 * d) If there are not segment override prefixes or they cannot be used, the
 *    default segment register associated with the operand register is used.
 *
 * The function checks first if segment override prefixes can be used with the
 * operand indicated by @regoff. If allowed, obtain such overridden segment
 * register index. Lastly, if not prefixes were found or cannot be used, resolve
 * the segment register index to use based on the defaults described in the
 * Intel documentation. In long mode, all segment register indexes will be
 * ignored, except if overrides were found for FS or GS. All these operations
 * are done using helper functions.
 *
 * The operand register, @regoff, is represented as the offset from the base of
 * pt_regs.
 *
 * As stated, the main use of this function is to determine the segment register
 * index based on the instruction, its operands and prefixes. Hence, @insn
 * must be valid. However, if @regoff indicates rIP, we don't need to inspect
 * @insn at all as in this case CS is used in all cases. This case is checked
 * before proceeding further.
 *
 * Please note that this function does not return the value in the segment
 * register (i.e., the segment selector) but our defined index. The segment
 * selector needs to be obtained using get_segment_selector() and passing the
 * segment register index resolved by this function.
 *
 * Returns:
 *
 * An index identifying the segment register to use, among CS, SS, DS,
 * ES, FS, or GS. INAT_SEG_REG_IGNORE is returned if running in long mode.
 *
 * -EINVAL in case of error.
 */
static int resolve_seg_reg(struct insn *insn, struct pt_regs *regs, int regoff)
{
	int idx;

	/*
	 * In the unlikely event of having to resolve the segment register
	 * index for rIP, do it first. Segment override prefixes should not
	 * be used. Hence, it is not necessary to inspect the instruction,
	 * which may be invalid at this point.
	 */
	if (regoff == offsetof(struct pt_regs, ip)) {
		if (any_64bit_mode(regs))
			return INAT_SEG_REG_IGNORE;
		else
			return INAT_SEG_REG_CS;
	}

	if (!insn)
		return -EINVAL;

	if (!check_seg_overrides(insn, regoff))
		return resolve_default_seg(insn, regs, regoff);

	idx = get_seg_reg_override_idx(insn);
	if (idx < 0)
		return idx;

	if (idx == INAT_SEG_REG_DEFAULT)
		return resolve_default_seg(insn, regs, regoff);

	/*
	 * In long mode, segment override prefixes are ignored, except for
	 * overrides for FS and GS.
	 */
	if (any_64bit_mode(regs)) {
		if (idx != INAT_SEG_REG_FS &&
		    idx != INAT_SEG_REG_GS)
			idx = INAT_SEG_REG_IGNORE;
	}

	return idx;
}

/**
 * get_segment_selector() - obtain segment selector
 * @regs:		Register values as seen when entering kernel mode
 * @seg_reg_idx:	Segment register index to use
 *
 * Obtain the segment selector from any of the CS, SS, DS, ES, FS, GS segment
 * registers. In CONFIG_X86_32, the segment is obtained from either pt_regs or
 * kernel_vm86_regs as applicable. In CONFIG_X86_64, CS and SS are obtained
 * from pt_regs. DS, ES, FS and GS are obtained by reading the actual CPU
 * registers. This done for only for completeness as in CONFIG_X86_64 segment
 * registers are ignored.
 *
 * Returns:
 *
 * Value of the segment selector, including null when running in
 * long mode.
 *
 * -EINVAL on error.
 */
static short get_segment_selector(struct pt_regs *regs, int seg_reg_idx)
{
#ifdef CONFIG_X86_64
	unsigned short sel;

	switch (seg_reg_idx) {
	case INAT_SEG_REG_IGNORE:
		return 0;
	case INAT_SEG_REG_CS:
		return (unsigned short)(regs->cs & 0xffff);
	case INAT_SEG_REG_SS:
		return (unsigned short)(regs->ss & 0xffff);
	case INAT_SEG_REG_DS:
		savesegment(ds, sel);
		return sel;
	case INAT_SEG_REG_ES:
		savesegment(es, sel);
		return sel;
	case INAT_SEG_REG_FS:
		savesegment(fs, sel);
		return sel;
	case INAT_SEG_REG_GS:
		savesegment(gs, sel);
		return sel;
	default:
		return -EINVAL;
	}
#else /* CONFIG_X86_32 */
	struct kernel_vm86_regs *vm86regs = (struct kernel_vm86_regs *)regs;

	if (v8086_mode(regs)) {
		switch (seg_reg_idx) {
		case INAT_SEG_REG_CS:
			return (unsigned short)(regs->cs & 0xffff);
		case INAT_SEG_REG_SS:
			return (unsigned short)(regs->ss & 0xffff);
		case INAT_SEG_REG_DS:
			return vm86regs->ds;
		case INAT_SEG_REG_ES:
			return vm86regs->es;
		case INAT_SEG_REG_FS:
			return vm86regs->fs;
		case INAT_SEG_REG_GS:
			return vm86regs->gs;
		case INAT_SEG_REG_IGNORE:
		default:
			return -EINVAL;
		}
	}

	switch (seg_reg_idx) {
	case INAT_SEG_REG_CS:
		return (unsigned short)(regs->cs & 0xffff);
	case INAT_SEG_REG_SS:
		return (unsigned short)(regs->ss & 0xffff);
	case INAT_SEG_REG_DS:
		return (unsigned short)(regs->ds & 0xffff);
	case INAT_SEG_REG_ES:
		return (unsigned short)(regs->es & 0xffff);
	case INAT_SEG_REG_FS:
		return (unsigned short)(regs->fs & 0xffff);
	case INAT_SEG_REG_GS:
		return get_user_gs(regs);
	case INAT_SEG_REG_IGNORE:
	default:
		return -EINVAL;
	}
#endif /* CONFIG_X86_64 */
}

/**
 * get_desc() - Obtain contents of a segment descriptor
 * @out:	Segment descriptor contents on success
 * @sel:	Segment selector
 *
 * Given a segment selector, obtain a pointer to the segment descriptor.
 * Both global and local descriptor tables are supported.
 *
 * Returns:
 *
 * True on success, false on failure.
 *
 * NULL on error.
 */
static bool get_desc(struct desc_struct *out, unsigned short sel)
{
	struct desc_ptr gdt_desc = {0, 0};
	unsigned long desc_base;

#ifdef CONFIG_MODIFY_LDT_SYSCALL
	if ((sel & SEGMENT_TI_MASK) == SEGMENT_LDT) {
		bool success = false;
		struct ldt_struct *ldt;

		/* Bits [15:3] contain the index of the desired entry. */
		sel >>= 3;

		mutex_lock(&current->active_mm->context.lock);
		ldt = current->active_mm->context.ldt;
		if (ldt && sel < ldt->nr_entries) {
			*out = ldt->entries[sel];
			success = true;
		}

		mutex_unlock(&current->active_mm->context.lock);

		return success;
	}
#endif
	native_store_gdt(&gdt_desc);

	/*
	 * Segment descriptors have a size of 8 bytes. Thus, the index is
	 * multiplied by 8 to obtain the memory offset of the desired descriptor
	 * from the base of the GDT. As bits [15:3] of the segment selector
	 * contain the index, it can be regarded as multiplied by 8 already.
	 * All that remains is to clear bits [2:0].
	 */
	desc_base = sel & ~(SEGMENT_RPL_MASK | SEGMENT_TI_MASK);

	if (desc_base > gdt_desc.size)
		return false;

	*out = *(struct desc_struct *)(gdt_desc.address + desc_base);
	return true;
}

/**
 * insn_get_seg_base() - Obtain base address of segment descriptor.
 * @regs:		Register values as seen when entering kernel mode
 * @seg_reg_idx:	Index of the segment register pointing to seg descriptor
 *
 * Obtain the base address of the segment as indicated by the segment descriptor
 * pointed by the segment selector. The segment selector is obtained from the
 * input segment register index @seg_reg_idx.
 *
 * Returns:
 *
 * In protected mode, base address of the segment. Zero in long mode,
 * except when FS or GS are used. In virtual-8086 mode, the segment
 * selector shifted 4 bits to the right.
 *
 * -1L in case of error.
 */
unsigned long insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx)
{
	struct desc_struct desc;
	short sel;

	sel = get_segment_selector(regs, seg_reg_idx);
	if (sel < 0)
		return -1L;

	if (v8086_mode(regs))
		/*
		 * Base is simply the segment selector shifted 4
		 * bits to the right.
		 */
		return (unsigned long)(sel << 4);

	if (any_64bit_mode(regs)) {
		/*
		 * Only FS or GS will have a base address, the rest of
		 * the segments' bases are forced to 0.
		 */
		unsigned long base;

		if (seg_reg_idx == INAT_SEG_REG_FS) {
			rdmsrl(MSR_FS_BASE, base);
		} else if (seg_reg_idx == INAT_SEG_REG_GS) {
			/*
			 * swapgs was called at the kernel entry point. Thus,
			 * MSR_KERNEL_GS_BASE will have the user-space GS base.
			 */
			if (user_mode(regs))
				rdmsrl(MSR_KERNEL_GS_BASE, base);
			else
				rdmsrl(MSR_GS_BASE, base);
		} else {
			base = 0;
		}
		return base;
	}

	/* In protected mode the segment selector cannot be null. */
	if (!sel)
		return -1L;

	if (!get_desc(&desc, sel))
		return -1L;

	return get_desc_base(&desc);
}

/**
 * get_seg_limit() - Obtain the limit of a segment descriptor
 * @regs:		Register values as seen when entering kernel mode
 * @seg_reg_idx:	Index of the segment register pointing to seg descriptor
 *
 * Obtain the limit of the segment as indicated by the segment descriptor
 * pointed by the segment selector. The segment selector is obtained from the
 * input segment register index @seg_reg_idx.
 *
 * Returns:
 *
 * In protected mode, the limit of the segment descriptor in bytes.
 * In long mode and virtual-8086 mode, segment limits are not enforced. Thus,
 * limit is returned as -1L to imply a limit-less segment.
 *
 * Zero is returned on error.
 */
static unsigned long get_seg_limit(struct pt_regs *regs, int seg_reg_idx)
{
	struct desc_struct desc;
	unsigned long limit;
	short sel;

	sel = get_segment_selector(regs, seg_reg_idx);
	if (sel < 0)
		return 0;

	if (any_64bit_mode(regs) || v8086_mode(regs))
		return -1L;

	if (!sel)
		return 0;

	if (!get_desc(&desc, sel))
		return 0;

	/*
	 * If the granularity bit is set, the limit is given in multiples
	 * of 4096. This also means that the 12 least significant bits are
	 * not tested when checking the segment limits. In practice,
	 * this means that the segment ends in (limit << 12) + 0xfff.
	 */
	limit = get_desc_limit(&desc);
	if (desc.g)
		limit = (limit << 12) + 0xfff;

	return limit;
}

/**
 * insn_get_code_seg_params() - Obtain code segment parameters
 * @regs:	Structure with register values as seen when entering kernel mode
 *
 * Obtain address and operand sizes of the code segment. It is obtained from the
 * selector contained in the CS register in regs. In protected mode, the default
 * address is determined by inspecting the L and D bits of the segment
 * descriptor. In virtual-8086 mode, the default is always two bytes for both
 * address and operand sizes.
 *
 * Returns:
 *
 * An int containing ORed-in default parameters on success.
 *
 * -EINVAL on error.
 */
int insn_get_code_seg_params(struct pt_regs *regs)
{
	struct desc_struct desc;
	short sel;

	if (v8086_mode(regs))
		/* Address and operand size are both 16-bit. */
		return INSN_CODE_SEG_PARAMS(2, 2);

	sel = get_segment_selector(regs, INAT_SEG_REG_CS);
	if (sel < 0)
		return sel;

	if (!get_desc(&desc, sel))
		return -EINVAL;

	/*
	 * The most significant byte of the Type field of the segment descriptor
	 * determines whether a segment contains data or code. If this is a data
	 * segment, return error.
	 */
	if (!(desc.type & BIT(3)))
		return -EINVAL;

	switch ((desc.l << 1) | desc.d) {
	case 0: /*
		 * Legacy mode. CS.L=0, CS.D=0. Address and operand size are
		 * both 16-bit.
		 */
		return INSN_CODE_SEG_PARAMS(2, 2);
	case 1: /*
		 * Legacy mode. CS.L=0, CS.D=1. Address and operand size are
		 * both 32-bit.
		 */
		return INSN_CODE_SEG_PARAMS(4, 4);
	case 2: /*
		 * IA-32e 64-bit mode. CS.L=1, CS.D=0. Address size is 64-bit;
		 * operand size is 32-bit.
		 */
		return INSN_CODE_SEG_PARAMS(4, 8);
	case 3: /* Invalid setting. CS.L=1, CS.D=1 */
		fallthrough;
	default:
		return -EINVAL;
	}
}

/**
 * get_seg_base_limit() - obtain base address and limit of a segment
 * @insn:	Instruction. Must be valid.
 * @regs:	Register values as seen when entering kernel mode
 * @regoff:	Operand offset, in pt_regs, used to resolve segment descriptor
 * @base:	Obtained segment base
 * @limit:	Obtained segment limit
 *
 * Obtain the base address and limit of the segment associated with the operand
 * @regoff and, if any or allowed, override prefixes in @insn. This function is
 * different from insn_get_seg_base() as the latter does not resolve the segment
 * associated with the instruction operand. If a limit is not needed (e.g.,
 * when running in long mode), @limit can be NULL.
 *
 * Returns:
 *
 * 0 on success. @base and @limit will contain the base address and of the
 * resolved segment, respectively.
 *
 * -EINVAL on error.
 */
static int get_seg_base_limit(struct insn *insn, struct pt_regs *regs,
			      int regoff, unsigned long *base,
			      unsigned long *limit)
{
	int seg_reg_idx;

	if (!base)
		return -EINVAL;

	seg_reg_idx = resolve_seg_reg(insn, regs, regoff);
	if (seg_reg_idx < 0)
		return seg_reg_idx;

	*base = insn_get_seg_base(regs, seg_reg_idx);
	if (*base == -1L)
		return -EINVAL;

	if (!limit)
		return 0;

	*limit = get_seg_limit(regs, seg_reg_idx);
	if (!(*limit))
		return -EINVAL;

	return 0;
}

/**
 * insn_fetch_from_user() - Copy instruction bytes from user-space memory
 * @regs:	Structure with register values as seen when entering kernel mode
 * @buf:	Array to store the fetched instruction
 *
 * Gets the linear address of the instruction and copies the instruction bytes
 * to the buf.
 *
 * Returns:
 *
 * - number of instruction bytes copied.
 * - 0 if nothing was copied.
 * - -EINVAL if the linear address of the instruction could not be calculated
 */
int insn_fetch_from_user(struct pt_regs *regs, unsigned char buf[MAX_INSN_SIZE])
{
	unsigned long ip;
	int not_copied;

	if (insn_get_effective_ip(regs, &ip))
		return -EINVAL;

	not_copied = copy_from_user(buf, (void __user *)ip, MAX_INSN_SIZE);

	return MAX_INSN_SIZE - not_copied;
}

/**
 * insn_fetch_from_user_inatomic() - Copy instruction bytes from user-space memory
 *                                   while in atomic code
 * @regs:	Structure with register values as seen when entering kernel mode
 * @buf:	Array to store the fetched instruction
 *
 * Gets the linear address of the instruction and copies the instruction bytes
 * to the buf. This function must be used in atomic context.
 *
 * Returns:
 *
 *  - number of instruction bytes copied.
 *  - 0 if nothing was copied.
 *  - -EINVAL if the linear address of the instruction could not be calculated.
 */
int insn_fetch_from_user_inatomic(struct pt_regs *regs, unsigned char buf[MAX_INSN_SIZE])
{
	unsigned long ip;
	int not_copied;

	if (insn_get_effective_ip(regs, &ip))
		return -EINVAL;

	not_copied = __copy_from_user_inatomic(buf, (void __user *)ip, MAX_INSN_SIZE);

	return MAX_INSN_SIZE - not_copied;
}

/**
 * insn_decode_from_regs() - Decode an instruction
 * @insn:	Structure to store decoded instruction
 * @regs:	Structure with register values as seen when entering kernel mode
 * @buf:	Buffer containing the instruction bytes
 * @buf_size:   Number of instruction bytes available in buf
 *
 * Decodes the instruction provided in buf and stores the decoding results in
 * insn. Also determines the correct address and operand sizes.
 *
 * Returns:
 *
 * True if instruction was decoded, False otherwise.
 */
bool insn_decode_from_regs(struct insn *insn, struct pt_regs *regs,
			   unsigned char buf[MAX_INSN_SIZE], int buf_size)
{
	int seg_defs;

	insn_init(insn, buf, buf_size, user_64bit_mode(regs));

	/*
	 * Override the default operand and address sizes with what is specified
	 * in the code segment descriptor. The instruction decoder only sets
	 * the address size it to either 4 or 8 address bytes and does nothing
	 * for the operand bytes. This OK for most of the cases, but we could
	 * have special cases where, for instance, a 16-bit code segment
	 * descriptor is used.
	 * If there is an address override prefix, the instruction decoder
	 * correctly updates these values, even for 16-bit defaults.
	 */
	seg_defs = insn_get_code_seg_params(regs);
	if (seg_defs == -EINVAL)
		return false;

	insn->addr_bytes = INSN_CODE_SEG_ADDR_SZ(seg_defs);
	insn->opnd_bytes = INSN_CODE_SEG_OPND_SZ(seg_defs);

	if (insn_get_length(insn))
		return false;

	if (buf_size < insn->length)
		return false;

	return true;
}

/*
 * Utility functions for x86 operand and address decoding
 *
 * Copyright (C) Intel Corporation 2017
 */

enum reg_type {
	REG_TYPE_RM = 0,
	REG_TYPE_REG,
	REG_TYPE_INDEX,
	REG_TYPE_BASE,
};

/**
 * is_string_insn() - Determine if instruction is a string instruction
 * @insn:	Instruction containing the opcode to inspect
 *
 * Returns:
 *
 * true if the instruction, determined by the opcode, is any of the
 * string instructions as defined in the Intel Software Development manual.
 * False otherwise.
 */
static bool is_string_insn(struct insn *insn)
{
	insn_get_opcode(insn);

	/* All string instructions have a 1-byte opcode. */
	if (insn->opcode.nbytes != 1)
		return false;

	switch (insn->opcode.bytes[0]) {
	case 0x6c ... 0x6f:	/* INS, OUTS */
	case 0xa4 ... 0xa7:	/* MOVS, CMPS */
	case 0xaa ... 0xaf:	/* STOS, LODS, SCAS */
		return true;
	default:
		return false;
	}
}

/**
 * insn_has_rep_prefix() - Determine if instruction has a REP prefix
 * @insn:	Instruction containing the prefix to inspect
 *
 * Returns:
 *
 * true if the instruction has a REP prefix, false if not.
 */
bool insn_has_rep_prefix(struct insn *insn)
{
	insn_byte_t p;
	int i;

	insn_get_prefixes(insn);

	for_each_insn_prefix(insn, i, p) {
		if (p == 0xf2 || p == 0xf3)
			return true;
	}

	return false;
}

static int get_reg_offset(struct insn *insn, struct pt_regs *regs,
			  enum reg_type type)
{
	int regno = 0;

	static const int regoff[] = {
		offsetof(struct pt_regs, ax),
		offsetof(struct pt_regs, cx),
		offsetof(struct pt_regs, dx),
		offsetof(struct pt_regs, bx),
		offsetof(struct pt_regs, sp),
		offsetof(struct pt_regs, bp),
		offsetof(struct pt_regs, si),
		offsetof(struct pt_regs, di),
#ifdef CONFIG_X86_64
		offsetof(struct pt_regs, r8),
		offsetof(struct pt_regs, r9),
		offsetof(struct pt_regs, r10),
		offsetof(struct pt_regs, r11),
		offsetof(struct pt_regs, r12),
		offsetof(struct pt_regs, r13),
		offsetof(struct pt_regs, r14),
		offsetof(struct pt_regs, r15),
#endif
	};
	int nr_registers = ARRAY_SIZE(regoff);
	/*
	 * Don't possibly decode a 32-bit instructions as
	 * reading a 64-bit-only register.
	 */
	if (IS_ENABLED(CONFIG_X86_64) && !insn->x86_64)
		nr_registers -= 8;

	switch (type) {
	case REG_TYPE_RM:
		regno = X86_MODRM_RM(insn->modrm.value);

		/*
		 * ModRM.mod == 0 and ModRM.rm == 5 means a 32-bit displacement
		 * follows the ModRM byte.
		 */
		if (!X86_MODRM_MOD(insn->modrm.value) && regno == 5)
			return -EDOM;

		if (X86_REX_B(insn->rex_prefix.value))
			regno += 8;
		break;

	case REG_TYPE_REG:
		regno = X86_MODRM_REG(insn->modrm.value);

		if (X86_REX_R(insn->rex_prefix.value))
			regno += 8;
		break;

	case REG_TYPE_INDEX:
		regno = X86_SIB_INDEX(insn->sib.value);
		if (X86_REX_X(insn->rex_prefix.value))
			regno += 8;

		/*
		 * If ModRM.mod != 3 and SIB.index = 4 the scale*index
		 * portion of the address computation is null. This is
		 * true only if REX.X is 0. In such a case, the SIB index
		 * is used in the address computation.
		 */
		if (X86_MODRM_MOD(insn->modrm.value) != 3 && regno == 4)
			return -EDOM;
		break;

	case REG_TYPE_BASE:
		regno = X86_SIB_BASE(insn->sib.value);
		/*
		 * If ModRM.mod is 0 and SIB.base == 5, the base of the
		 * register-indirect addressing is 0. In this case, a
		 * 32-bit displacement follows the SIB byte.
		 */
		if (!X86_MODRM_MOD(insn->modrm.value) && regno == 5)
			return -EDOM;

		if (X86_REX_B(insn->rex_prefix.value))
			regno += 8;
		break;

	default:
		pr_err_ratelimited("invalid register type: %d\n", type);
		return -EINVAL;
	}

	if (regno >= nr_registers) {
		WARN_ONCE(1, "decoded an instruction with an invalid register");
		return -EINVAL;
	}
	return regoff[regno];
}

/**
 * insn_get_modrm_rm_off() - Obtain register in r/m part of the ModRM byte
 * @insn:	Instruction containing the ModRM byte
 * @regs:	Register values as seen when entering kernel mode
 *
 * Returns:
 *
 * The register indicated by the r/m part of the ModRM byte. The
 * register is obtained as an offset from the base of pt_regs. In specific
 * cases, the returned value can be -EDOM to indicate that the particular value
 * of ModRM does not refer to a register and shall be ignored.
 */
int insn_get_modrm_rm_off(struct insn *insn, struct pt_regs *regs)
{
	return get_reg_offset(insn, regs, REG_TYPE_RM);
}

/**
 * get_reg_offset_16() - Obtain offset of register indicated by instruction
 * @insn:	Instruction containing ModRM byte
 * @regs:	Register values as seen when entering kernel mode
 * @offs1:	Offset of the first operand register
 * @offs2:	Offset of the second operand register, if applicable
 *
 * Obtain the offset, in pt_regs, of the registers indicated by the ModRM byte
 * in @insn. This function is to be used with 16-bit address encodings. The
 * @offs1 and @offs2 will be written with the offset of the two registers
 * indicated by the instruction. In cases where any of the registers is not
 * referenced by the instruction, the value will be set to -EDOM.
 *
 * Returns:
 *
 * 0 on success, -EINVAL on error.
 */
static int get_reg_offset_16(struct insn *insn, struct pt_regs *regs,
			     int *offs1, int *offs2)
{
	/*
	 * 16-bit addressing can use one or two registers. Specifics of
	 * encodings are given in Table 2-1. "16-Bit Addressing Forms with the
	 * ModR/M Byte" of the Intel Software Development Manual.
	 */
	static const int regoff1[] = {
		offsetof(struct pt_regs, bx),
		offsetof(struct pt_regs, bx),
		offsetof(struct pt_regs, bp),
		offsetof(struct pt_regs, bp),
		offsetof(struct pt_regs, si),
		offsetof(struct pt_regs, di),
		offsetof(struct pt_regs, bp),
		offsetof(struct pt_regs, bx),
	};

	static const int regoff2[] = {
		offsetof(struct pt_regs, si),
		offsetof(struct pt_regs, di),
		offsetof(struct pt_regs, si),
		offsetof(struct pt_regs, di),
		-EDOM,
		-EDOM,
		-EDOM,
		-EDOM,
	};

	if (!offs1 || !offs2)
		return -EINVAL;

	/* Operand is a register, use the generic function. */
	if (X86_MODRM_MOD(insn->modrm.value) == 3) {
		*offs1 = insn_get_modrm_rm_off(insn, regs);
		*offs2 = -EDOM;
		return 0;
	}

	*offs1 = regoff1[X86_MODRM_RM(insn->modrm.value)];
	*offs2 = regoff2[X86_MODRM_RM(insn->modrm.value)];

	/*
	 * If ModRM.mod is 0 and ModRM.rm is 110b, then we use displacement-
	 * only addressing. This means that no registers are involved in
	 * computing the effective address. Thus, ensure that the first
	 * register offset is invalid. The second register offset is already
	 * invalid under the aforementioned conditions.
	 */
	if ((X86_MODRM_MOD(insn->modrm.value) == 0) &&
	    (X86_MODRM_RM(insn->modrm.value) == 6))
		*offs1 = -EDOM;

	return 0;
}

/**
 * insn_get_modrm_reg_off() - Obtain register in reg part of the ModRM byte
 * @insn:	Instruction containing the ModRM byte
 * @regs:	Register values as seen when entering kernel mode
 *
 * Returns:
 *
 * The register indicated by the reg part of the ModRM byte. The
 * register is obtained as an offset from the base of pt_regs.
 */
int insn_get_modrm_reg_off(struct insn *insn, struct pt_regs *regs)
{
	return get_reg_offset(insn, regs, REG_TYPE_REG);
}

/**
 * get_eff_addr_reg() - Obtain effective address from register operand
 * @insn:	Instruction. Must be valid.
 * @regs:	Register values as seen when entering kernel mode
 * @regoff:	Obtained operand offset, in pt_regs, with the effective address
 * @eff_addr:	Obtained effective address
 *
 * Obtain the effective address stored in the register operand as indicated by
 * the ModRM byte. This function is to be used only with register addressing
 * (i.e.,  ModRM.mod is 3). The effective address is saved in @eff_addr. The
 * register operand, as an offset from the base of pt_regs, is saved in @regoff;
 * such offset can then be used to resolve the segment associated with the
 * operand. This function can be used with any of the supported address sizes
 * in x86.
 *
 * Returns:
 *
 * 0 on success. @eff_addr will have the effective address stored in the
 * operand indicated by ModRM. @regoff will have such operand as an offset from
 * the base of pt_regs.
 *
 * -EINVAL on error.
 */
static int get_eff_addr_reg(struct insn *insn, struct pt_regs *regs,
			    int *regoff, long *eff_addr)
{
	int ret;

	ret = insn_get_modrm(insn);
	if (ret)
		return ret;

	if (X86_MODRM_MOD(insn->modrm.value) != 3)
		return -EINVAL;

	*regoff = get_reg_offset(insn, regs, REG_TYPE_RM);
	if (*regoff < 0)
		return -EINVAL;

	/* Ignore bytes that are outside the address size. */
	if (insn->addr_bytes == 2)
		*eff_addr = regs_get_register(regs, *regoff) & 0xffff;
	else if (insn->addr_bytes == 4)
		*eff_addr = regs_get_register(regs, *regoff) & 0xffffffff;
	else /* 64-bit address */
		*eff_addr = regs_get_register(regs, *regoff);

	return 0;
}

/**
 * get_eff_addr_modrm() - Obtain referenced effective address via ModRM
 * @insn:	Instruction. Must be valid.
 * @regs:	Register values as seen when entering kernel mode
 * @regoff:	Obtained operand offset, in pt_regs, associated with segment
 * @eff_addr:	Obtained effective address
 *
 * Obtain the effective address referenced by the ModRM byte of @insn. After
 * identifying the registers involved in the register-indirect memory reference,
 * its value is obtained from the operands in @regs. The computed address is
 * stored @eff_addr. Also, the register operand that indicates the associated
 * segment is stored in @regoff, this parameter can later be used to determine
 * such segment.
 *
 * Returns:
 *
 * 0 on success. @eff_addr will have the referenced effective address. @regoff
 * will have a register, as an offset from the base of pt_regs, that can be used
 * to resolve the associated segment.
 *
 * -EINVAL on error.
 */
static int get_eff_addr_modrm(struct insn *insn, struct pt_regs *regs,
			      int *regoff, long *eff_addr)
{
	long tmp;
	int ret;

	if (insn->addr_bytes != 8 && insn->addr_bytes != 4)
		return -EINVAL;

	ret = insn_get_modrm(insn);
	if (ret)
		return ret;

	if (X86_MODRM_MOD(insn->modrm.value) > 2)
		return -EINVAL;

	*regoff = get_reg_offset(insn, regs, REG_TYPE_RM);

	/*
	 * -EDOM means that we must ignore the address_offset. In such a case,
	 * in 64-bit mode the effective address relative to the rIP of the
	 * following instruction.
	 */
	if (*regoff == -EDOM) {
		if (any_64bit_mode(regs))
			tmp = regs->ip + insn->length;
		else
			tmp = 0;
	} else if (*regoff < 0) {
		return -EINVAL;
	} else {
		tmp = regs_get_register(regs, *regoff);
	}

	if (insn->addr_bytes == 4) {
		int addr32 = (int)(tmp & 0xffffffff) + insn->displacement.value;

		*eff_addr = addr32 & 0xffffffff;
	} else {
		*eff_addr = tmp + insn->displacement.value;
	}

	return 0;
}

/**
 * get_eff_addr_modrm_16() - Obtain referenced effective address via ModRM
 * @insn:	Instruction. Must be valid.
 * @regs:	Register values as seen when entering kernel mode
 * @regoff:	Obtained operand offset, in pt_regs, associated with segment
 * @eff_addr:	Obtained effective address
 *
 * Obtain the 16-bit effective address referenced by the ModRM byte of @insn.
 * After identifying the registers involved in the register-indirect memory
 * reference, its value is obtained from the operands in @regs. The computed
 * address is stored @eff_addr. Also, the register operand that indicates
 * the associated segment is stored in @regoff, this parameter can later be used
 * to determine such segment.
 *
 * Returns:
 *
 * 0 on success. @eff_addr will have the referenced effective address. @regoff
 * will have a register, as an offset from the base of pt_regs, that can be used
 * to resolve the associated segment.
 *
 * -EINVAL on error.
 */
static int get_eff_addr_modrm_16(struct insn *insn, struct pt_regs *regs,
				 int *regoff, short *eff_addr)
{
	int addr_offset1, addr_offset2, ret;
	short addr1 = 0, addr2 = 0, displacement;

	if (insn->addr_bytes != 2)
		return -EINVAL;

	insn_get_modrm(insn);

	if (!insn->modrm.nbytes)
		return -EINVAL;

	if (X86_MODRM_MOD(insn->modrm.value) > 2)
		return -EINVAL;

	ret = get_reg_offset_16(insn, regs, &addr_offset1, &addr_offset2);
	if (ret < 0)
		return -EINVAL;

	/*
	 * Don't fail on invalid offset values. They might be invalid because
	 * they cannot be used for this particular value of ModRM. Instead, use
	 * them in the computation only if they contain a valid value.
	 */
	if (addr_offset1 != -EDOM)
		addr1 = regs_get_register(regs, addr_offset1) & 0xffff;

	if (addr_offset2 != -EDOM)
		addr2 = regs_get_register(regs, addr_offset2) & 0xffff;

	displacement = insn->displacement.value & 0xffff;
	*eff_addr = addr1 + addr2 + displacement;

	/*
	 * The first operand register could indicate to use of either SS or DS
	 * registers to obtain the segment selector.  The second operand
	 * register can only indicate the use of DS. Thus, the first operand
	 * will be used to obtain the segment selector.
	 */
	*regoff = addr_offset1;

	return 0;
}

/**
 * get_eff_addr_sib() - Obtain referenced effective address via SIB
 * @insn:	Instruction. Must be valid.
 * @regs:	Register values as seen when entering kernel mode
 * @regoff:	Obtained operand offset, in pt_regs, associated with segment
 * @eff_addr:	Obtained effective address
 *
 * Obtain the effective address referenced by the SIB byte of @insn. After
 * identifying the registers involved in the indexed, register-indirect memory
 * reference, its value is obtained from the operands in @regs. The computed
 * address is stored @eff_addr. Also, the register operand that indicates the
 * associated segment is stored in @regoff, this parameter can later be used to
 * determine such segment.
 *
 * Returns:
 *
 * 0 on success. @eff_addr will have the referenced effective address.
 * @base_offset will have a register, as an offset from the base of pt_regs,
 * that can be used to resolve the associated segment.
 *
 * Negative value on error.
 */
static int get_eff_addr_sib(struct insn *insn, struct pt_regs *regs,
			    int *base_offset, long *eff_addr)
{
	long base, indx;
	int indx_offset;
	int ret;

	if (insn->addr_bytes != 8 && insn->addr_bytes != 4)
		return -EINVAL;

	ret = insn_get_modrm(insn);
	if (ret)
		return ret;

	if (!insn->modrm.nbytes)
		return -EINVAL;

	if (X86_MODRM_MOD(insn->modrm.value) > 2)
		return -EINVAL;

	ret = insn_get_sib(insn);
	if (ret)
		return ret;

	if (!insn->sib.nbytes)
		return -EINVAL;

	*base_offset = get_reg_offset(insn, regs, REG_TYPE_BASE);
	indx_offset = get_reg_offset(insn, regs, REG_TYPE_INDEX);

	/*
	 * Negative values in the base and index offset means an error when
	 * decoding the SIB byte. Except -EDOM, which means that the registers
	 * should not be used in the address computation.
	 */
	if (*base_offset == -EDOM)
		base = 0;
	else if (*base_offset < 0)
		return -EINVAL;
	else
		base = regs_get_register(regs, *base_offset);

	if (indx_offset == -EDOM)
		indx = 0;
	else if (indx_offset < 0)
		return -EINVAL;
	else
		indx = regs_get_register(regs, indx_offset);

	if (insn->addr_bytes == 4) {
		int addr32, base32, idx32;

		base32 = base & 0xffffffff;
		idx32 = indx & 0xffffffff;

		addr32 = base32 + idx32 * (1 << X86_SIB_SCALE(insn->sib.value));
		addr32 += insn->displacement.value;

		*eff_addr = addr32 & 0xffffffff;
	} else {
		*eff_addr = base + indx * (1 << X86_SIB_SCALE(insn->sib.value));
		*eff_addr += insn->displacement.value;
	}

	return 0;
}

/**
 * get_addr_ref_16() - Obtain the 16-bit address referred by instruction
 * @insn:	Instruction containing ModRM byte and displacement
 * @regs:	Register values as seen when entering kernel mode
 *
 * This function is to be used with 16-bit address encodings. Obtain the memory
 * address referred by the instruction's ModRM and displacement bytes. Also, the
 * segment used as base is determined by either any segment override prefixes in
 * @insn or the default segment of the registers involved in the address
 * computation. In protected mode, segment limits are enforced.
 *
 * Returns:
 *
 * Linear address referenced by the instruction operands on success.
 *
 * -1L on error.
 */
static void __user *get_addr_ref_16(struct insn *insn, struct pt_regs *regs)
{
	unsigned long linear_addr = -1L, seg_base, seg_limit;
	int ret, regoff;
	short eff_addr;
	long tmp;

	if (insn_get_displacement(insn))
		goto out;

	if (insn->addr_bytes != 2)
		goto out;

	if (X86_MODRM_MOD(insn->modrm.value) == 3) {
		ret = get_eff_addr_reg(insn, regs, &regoff, &tmp);
		if (ret)
			goto out;

		eff_addr = tmp;
	} else {
		ret = get_eff_addr_modrm_16(insn, regs, &regoff, &eff_addr);
		if (ret)
			goto out;
	}

	ret = get_seg_base_limit(insn, regs, regoff, &seg_base, &seg_limit);
	if (ret)
		goto out;

	/*
	 * Before computing the linear address, make sure the effective address
	 * is within the limits of the segment. In virtual-8086 mode, segment
	 * limits are not enforced. In such a case, the segment limit is -1L to
	 * reflect this fact.
	 */
	if ((unsigned long)(eff_addr & 0xffff) > seg_limit)
		goto out;

	linear_addr = (unsigned long)(eff_addr & 0xffff) + seg_base;

	/* Limit linear address to 20 bits */
	if (v8086_mode(regs))
		linear_addr &= 0xfffff;

out:
	return (void __user *)linear_addr;
}

/**
 * get_addr_ref_32() - Obtain a 32-bit linear address
 * @insn:	Instruction with ModRM, SIB bytes and displacement
 * @regs:	Register values as seen when entering kernel mode
 *
 * This function is to be used with 32-bit address encodings to obtain the
 * linear memory address referred by the instruction's ModRM, SIB,
 * displacement bytes and segment base address, as applicable. If in protected
 * mode, segment limits are enforced.
 *
 * Returns:
 *
 * Linear address referenced by instruction and registers on success.
 *
 * -1L on error.
 */
static void __user *get_addr_ref_32(struct insn *insn, struct pt_regs *regs)
{
	unsigned long linear_addr = -1L, seg_base, seg_limit;
	int eff_addr, regoff;
	long tmp;
	int ret;

	if (insn->addr_bytes != 4)
		goto out;

	if (X86_MODRM_MOD(insn->modrm.value) == 3) {
		ret = get_eff_addr_reg(insn, regs, &regoff, &tmp);
		if (ret)
			goto out;

		eff_addr = tmp;

	} else {
		if (insn->sib.nbytes) {
			ret = get_eff_addr_sib(insn, regs, &regoff, &tmp);
			if (ret)
				goto out;

			eff_addr = tmp;
		} else {
			ret = get_eff_addr_modrm(insn, regs, &regoff, &tmp);
			if (ret)
				goto out;

			eff_addr = tmp;
		}
	}

	ret = get_seg_base_limit(insn, regs, regoff, &seg_base, &seg_limit);
	if (ret)
		goto out;

	/*
	 * In protected mode, before computing the linear address, make sure
	 * the effective address is within the limits of the segment.
	 * 32-bit addresses can be used in long and virtual-8086 modes if an
	 * address override prefix is used. In such cases, segment limits are
	 * not enforced. When in virtual-8086 mode, the segment limit is -1L
	 * to reflect this situation.
	 *
	 * After computed, the effective address is treated as an unsigned
	 * quantity.
	 */
	if (!any_64bit_mode(regs) && ((unsigned int)eff_addr > seg_limit))
		goto out;

	/*
	 * Even though 32-bit address encodings are allowed in virtual-8086
	 * mode, the address range is still limited to [0x-0xffff].
	 */
	if (v8086_mode(regs) && (eff_addr & ~0xffff))
		goto out;

	/*
	 * Data type long could be 64 bits in size. Ensure that our 32-bit
	 * effective address is not sign-extended when computing the linear
	 * address.
	 */
	linear_addr = (unsigned long)(eff_addr & 0xffffffff) + seg_base;

	/* Limit linear address to 20 bits */
	if (v8086_mode(regs))
		linear_addr &= 0xfffff;

out:
	return (void __user *)linear_addr;
}

/**
 * get_addr_ref_64() - Obtain a 64-bit linear address
 * @insn:	Instruction struct with ModRM and SIB bytes and displacement
 * @regs:	Structure with register values as seen when entering kernel mode
 *
 * This function is to be used with 64-bit address encodings to obtain the
 * linear memory address referred by the instruction's ModRM, SIB,
 * displacement bytes and segment base address, as applicable.
 *
 * Returns:
 *
 * Linear address referenced by instruction and registers on success.
 *
 * -1L on error.
 */
#ifndef CONFIG_X86_64
static void __user *get_addr_ref_64(struct insn *insn, struct pt_regs *regs)
{
	return (void __user *)-1L;
}
#else
static void __user *get_addr_ref_64(struct insn *insn, struct pt_regs *regs)
{
	unsigned long linear_addr = -1L, seg_base;
	int regoff, ret;
	long eff_addr;

	if (insn->addr_bytes != 8)
		goto out;

	if (X86_MODRM_MOD(insn->modrm.value) == 3) {
		ret = get_eff_addr_reg(insn, regs, &regoff, &eff_addr);
		if (ret)
			goto out;

	} else {
		if (insn->sib.nbytes) {
			ret = get_eff_addr_sib(insn, regs, &regoff, &eff_addr);
			if (ret)
				goto out;
		} else {
			ret = get_eff_addr_modrm(insn, regs, &regoff, &eff_addr);
			if (ret)
				goto out;
		}

	}

	ret = get_seg_base_limit(insn, regs, regoff, &seg_base, NULL);
	if (ret)
		goto out;

	linear_addr = (unsigned long)eff_addr + seg_base;

out:
	return (void __user *)linear_addr;
}
#endif /* CONFIG_X86_64 */

/**
 * insn_get_addr_ref() - Obtain the linear address referred by instruction
 * @insn:	Instruction structure containing ModRM byte and displacement
 * @regs:	Structure with register values as seen when entering kernel mode
 *
 * Obtain the linear address referred by the instruction's ModRM, SIB and
 * displacement bytes, and segment base, as applicable. In protected mode,
 * segment limits are enforced.
 *
 * Returns:
 *
 * Linear address referenced by instruction and registers on success.
 *
 * -1L on error.
 */
void __user *insn_get_addr_ref(struct insn *insn, struct pt_regs *regs)
{
	if (!insn || !regs)
		return (void __user *)-1L;

	switch (insn->addr_bytes) {
	case 2:
		return get_addr_ref_16(insn, regs);
	case 4:
		return get_addr_ref_32(insn, regs);
	case 8:
		return get_addr_ref_64(insn, regs);
	default:
		return (void __user *)-1L;
	}
}

static int insn_get_effective_ip(struct pt_regs *regs, unsigned long *ip)
{
	unsigned long seg_base = 0;

	/*
	 * If not in user-space long mode, a custom code segment could be in
	 * use. This is true in protected mode (if the process defined a local
	 * descriptor table), or virtual-8086 mode. In most of the cases
	 * seg_base will be zero as in USER_CS.
	 */
	if (!user_64bit_mode(regs)) {
		seg_base = insn_get_seg_base(regs, INAT_SEG_REG_CS);
		if (seg_base == -1L)
			return -EINVAL;
	}

	*ip = seg_base + regs->ip;

	return 0;
}

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 *
 * This file is not compiled stand-alone. It contains code shared
 * between the pre-decompression boot code and the running Linux kernel
 * and is included directly into both code-bases.
 */

static void terminate(unsigned reason)
{
	/* Request Guest Termination from Hypvervisor */
	write_ghcb_msr(GHCB_SEV_TERMINATE);
	VMGEXIT();

	while (true)
		asm volatile("hlt\n");
}

static bool sev_es_negotiate_protocol(void)
{
	u64 oldval = read_ghcb_msr();
	bool ret = false;
	u64 val;

	/* Do the GHCB protocol version negotiation */
	write_ghcb_msr(GHCB_SEV_INFO_REQ);
	VMGEXIT();
	val = read_ghcb_msr();

	if (GHCB_INFO(val) != GHCB_SEV_INFO)
		goto out;

	if (GHCB_PROTO_OUR > GHCB_PROTO_MAX(val) ||
	    GHCB_PROTO_OUR < GHCB_PROTO_MIN(val))
		goto out;

	ret = true;

out:
	write_ghcb_msr(oldval);

	return ret;
}

static void ghcb_invalidate(struct ghcb *ghcb)
{
	memset(ghcb->save.valid_bitmap, 0, sizeof(ghcb->save.valid_bitmap));
}

static enum es_result decode_insn(struct es_em_ctxt *ctxt)
{
	unsigned char *rip = (unsigned char *)ctxt->regs->ip;
	int x86_64 = (ctxt->regs->cs == __KERNEL_CS);
	char buffer[MAX_INSN_SIZE];
	enum es_result ret;
	unsigned i;

	/* Fetch instruction */
	for (i = 0; i < MAX_INSN_SIZE; i++) {
		ret = es_fetch_insn_byte(ctxt, i, buffer);
		if (ret != ES_OK)
			return ret;
	}

	insn_init(&ctxt->insn, rip, 15, x86_64);
	insn_get_length(&ctxt->insn);

	ret = ctxt->insn.immediate.got ? ES_OK : ES_DECODE_FAILED;

	return ret;
}

static enum es_result init_em_ctxt(struct es_em_ctxt *ctxt,
				   struct pt_regs *regs)
{
	memset(ctxt, 0, sizeof(*ctxt));
	ctxt->regs = regs;

	return decode_insn(ctxt);
}

static void finish_insn(struct es_em_ctxt *ctxt)
{
	ctxt->regs->ip += ctxt->insn.length;
}

static enum es_result __maybe_unused
ghcb_hv_call(struct ghcb *ghcb, struct es_em_ctxt *ctxt,
	     u64 exit_code, u64 exit_info_1,
	     u64 exit_info_2)
{
	u64 oldval = read_ghcb_msr();
	enum es_result ret;

	ghcb_set_sw_exit_code(ghcb, exit_code);
	ghcb_set_sw_exit_info_1(ghcb, exit_info_1);
	ghcb_set_sw_exit_info_2(ghcb, exit_info_2);

	write_ghcb_msr(__pa(ghcb));
	VMGEXIT();

	write_ghcb_msr(oldval);

	if (ghcb->save.sw_exit_info_1 & 0xffffffff) {
		ctxt->fi.vector     = ghcb->save.sw_exit_info_1 >> 32;
		ctxt->fi.error_code = ghcb->save.sw_exit_info_2;
		ret = ES_EXCEPTION;
	} else {
		ret = ES_OK;
	}

	return ret;
}

/*
 * Boot VC Handler - This is the first VC handler during boot, there is no GHCB
 * page yet, so it only supports the MSR based communication with the
 * hypervisor and only the CPUID exit-code.
 */
void __init no_ghcb_vc_handler(struct pt_regs *regs)
{
	unsigned long val, old_val = read_ghcb_msr();
	unsigned long exit_code = regs->orig_ax;
	unsigned fn = lower_bits(regs->ax, 32);

	/* Only CPUID is supported via MSR protocol */
	if (exit_code != SVM_EXIT_CPUID)
		goto fail;

	write_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EAX));
	VMGEXIT();
	val = read_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->ax = copy_lower_bits(regs->ax, val >> 32, 32);

	write_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EBX));
	VMGEXIT();
	val = read_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->bx = copy_lower_bits(regs->bx, val >> 32, 32);

	write_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_ECX));
	VMGEXIT();
	val = read_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->cx = copy_lower_bits(regs->cx, val >> 32, 32);

	write_ghcb_msr(GHCB_CPUID_REQ(fn, GHCB_CPUID_REQ_EDX));
	VMGEXIT();
	val = read_ghcb_msr();
	if (GHCB_SEV_GHCB_RESP_CODE(val) != GHCB_SEV_CPUID_RESP)
		goto fail;
	regs->dx = copy_lower_bits(regs->dx, val >> 32, 32);

	regs->ip += 2;

	write_ghcb_msr(old_val);

	return;

fail:
	write_ghcb_msr(GHCB_SEV_TERMINATE);
	VMGEXIT();

	/* Shouldn't get here - if we do halt the machine */
	while (true)
		asm volatile("hlt\n");
}

static enum es_result __maybe_unused
insn_string_read(struct es_em_ctxt *ctxt,
		 void *src, char *buf,
		 unsigned data_size, unsigned count,
		 bool backwards)
{
	int i, b = backwards ? -1 : 1;
	enum es_result ret = ES_OK;

	for (i = 0; i < count; i++) {
		void *s = src + (i * data_size * b);
		char *d = buf + (i * data_size);

		ret = es_read_mem(ctxt, s, d, data_size);
		if (ret != ES_OK)
			break;
	}

	return ret;
}

static enum es_result __maybe_unused
insn_string_write(struct es_em_ctxt *ctxt,
		  void *dst, char *buf,
		  unsigned data_size, unsigned count,
		  bool backwards)
{
	int i, s = backwards ? -1 : 1;
	enum es_result ret = ES_OK;

	for (i = 0; i < count; i++) {
		void *d = dst + (i * data_size * s);
		char *b = buf + (i * data_size);

		ret = es_write_mem(ctxt, d, b, data_size);
		if (ret != ES_OK)
			break;
	}

	return ret;
}

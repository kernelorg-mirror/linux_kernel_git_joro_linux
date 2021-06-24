/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */
#ifndef __ASM_SEV_AP_JUMPTABLE_H
#define __ASM_SEV_AP_JUMPTABLE_H

#define	SEV_APJT_CS16	0x8
#define	SEV_APJT_DS16	0x10

#define SEV_APJT_ENTRY	0x10

#ifndef __ASSEMBLY__

struct sev_ap_jump_table_header {
	u16	reset_ip;
	u16	reset_cs;
	u16	gdt_offset;
};

#endif /* !__ASSEMBLY__ */

#endif /* __ASM_SEV_AP_JUMPTABLE_H */

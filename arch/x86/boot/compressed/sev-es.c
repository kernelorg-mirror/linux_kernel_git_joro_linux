/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD Encrypted Register State Support
 *
 * Author: Joerg Roedel <jroedel@suse.de>
 */

#include <asm/ptrace.h>
#include <asm/svm.h>
#include "misc.h"

void vc_handler(struct pt_regs *regs)
{
	/* Hang the machine for now */
	while (true)
		asm volatile("hlt\n");
}

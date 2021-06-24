/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ap_jump_table.lds
 *
 * Linker script for the SEV-ES AP Jump Table Code
 */

OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(ap_park_asm)

SECTIONS
{
	. = 0;
	.text : {
		*(.text)
		*(.text.*)
	}

	/DISCARD/ : {
		*(.note*)
		*(.debug*)
	}
}

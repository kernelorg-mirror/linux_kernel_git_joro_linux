/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BOOT_IDT_H
#define __BOOT_IDT_H

#ifdef __ASSEMBLY__

#define BOOT_VECTOR_VC 29

.macro BOOT32_IDT_ENTRY vector:req handler:req
	push	%eax
	push	%ebx
	push	%ecx
	push	%edx

	/* Handler address in %eax */
	leal	\handler(%ebp), %eax

	/* IDT entry address to %ebx */
	leal	boot32_idt(%ebp), %ebx
	addl	$(8*\vector), %ebx

	/* Build IDT entry, lower 4 bytes */
	movl	%eax, %edx
	andl	$0x0000ffff, %edx
	movl	$__KERNEL32_CS, %ecx
	shl	$16, %ecx
	orl	%ecx, %edx

	/* Store lower 4 bytes to IDT */
	movl	%edx, (%ebx)

	/* Build IDT entry, upper 4 bytes */
	movl	%eax, %edx
	andl	$0xffff0000, %edx
	orl	$0x00008e00, %edx

	/* Store upper 4 bytes to IDT */
	movl	%edx, 4(%ebx)

	pop	%edx
	pop	%ecx
	pop	%ebx
	pop	%eax
.endm

#endif

#endif

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BOOT_IDT_H
#define __BOOT_IDT_H

#ifdef __ASSEMBLY__

#define BOOT_VECTOR_VC 29

.macro BOOT_IDT_ENTRY vector:req handler:req lm=0
.if \lm == 0
	push	%eax
	push	%ebx
	push	%ecx
	push	%edx
.else
	pushq	%rax
	pushq	%rbx
	pushq	%rcx
	pushq	%rdx
.endif

	/* Handler address in %eax/%rax */
.if \lm == 0
	leal	\handler(%ebp), %eax
	/* IDT entry address to %ebx */
	leal	boot_idt(%ebp), %ebx
	addl	$(8*\vector), %ebx
.else
	leaq	\handler(%rip), %rax
	/* IDT entry address to %rbx */
	leaq	boot_idt(%rip), %rbx
	addq	$(16*\vector), %rbx
.endif


	/* Build IDT entry, first 4 bytes */
	movl	%eax, %edx
	andl	$0x0000ffff, %edx
.if \lm == 0
	movl	$__KERNEL32_CS, %ecx
.else
	movl	$__KERNEL_CS, %ecx
.endif
	shl	$16, %ecx
	orl	%ecx, %edx

	/* Store first 4 bytes to IDT */
.if \lm == 0
	movl	%edx, (%ebx)
.else
	movl	%edx, (%rbx)
.endif

	/* Build IDT entry, second 4 bytes */
	movl	%eax, %edx
	andl	$0xffff0000, %edx
	orl	$0x00008e00, %edx

	/* Store upper 4 bytes to IDT */
.if \lm == 0
	movl	%edx, 4(%ebx)
.else
	movl	%edx, 4(%rbx)

	/* Store upper bits of target offset */
	shrq	$32, %rax
	movl	%eax, 8(%rbx)
.endif

.if \lm == 0
	pop	%edx
	pop	%ecx
	pop	%ebx
	pop	%eax
.else
	popq	%rdx
	popq	%rcx
	popq	%rbx
	popq	%rax
.endif
.endm

#endif

#endif

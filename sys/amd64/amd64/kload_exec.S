/*
 * Copyright (c) 2011 - 2015
 *      Russell Cattelan Digital Elves LLC
 * Copyright (c) 2012 - 2015
 *      EMC Corp / Isilon Systems Division  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "assym.s"

#define	CR0_PG	0x80000000	/* PaGing enable */

#define X86_CR0_PE	0x00000001 /* Protection Enable */
#define X86_CR0_MP	0x00000002 /* Monitor Coprocessor */
#define X86_CR0_EM	0x00000004 /* Emulation */
#define X86_CR0_TS	0x00000008 /* Task Switched */
#define X86_CR0_ET	0x00000010 /* Extension Type */
#define X86_CR0_NE	0x00000020 /* Numeric Error */
#define X86_CR0_WP	0x00010000 /* Write Protect */
#define X86_CR0_AM	0x00040000 /* Alignment Mask */
#define X86_CR0_NW	0x20000000 /* Not Write-through */
#define X86_CR0_CD	0x40000000 /* Cache Disable */
#define X86_CR0_PG	0x80000000 /* Paging */

#define X86_CR4_PSE	0x00000010 /* enable page size extensions */
#define X86_CR4_PAE	0x00000020 /* enable physical address extensions */

        .globl relocate_kernel
relocate_kernel:
        /* Install the new page table. */
        movq	32(%rcx), %rax /* page table */
        movq	40(%rcx), %r9  /* address of control_page with new PT */
        movq	%rax, %cr3

        /*
         * Set cr4 to a known state:
         *  - page size extensions
         *  - physical address extension enabled
         */
        movq	$(X86_CR4_PSE | X86_CR4_PAE), %rax
        movq	%rax, %cr4

        /* Move the stack to the end of control page. */
        lea 4096(%r9), %rsp

        /* now save stuff onto the new stack */
        pushq	%rcx	/* arg 4 control page */
        pushq	%rdx	/* arg 3 code page */
        pushq	%rsi	/* arg 2 kern base */
        pushq	%rdi	/* arg 1 va_list */

        /* Zero out flags, and disable interrupts. */
        pushq $0
        popfq
        cli

        /* Install simple gdt. */
        movq	24(%r9), %rax	/* gdt */
        lgdt	(%rax)
        movq	56(%r9), %rax
        lidt	(%rax)		/* null idt */
        /*
         * Move to the code page.
         * code_page is based on new page table.
         */
        movq %rdx, %r8
        addq	$(identity_mapped - relocate_kernel), %r8
        /* Offset of code segment in new gdt. */
        pushq $0x08
        pushq %r8
        /* Jump to this spot in the new page. */
        lretq
identity_mapped:

        movq $0x10,%rax
        movq %rax,%ds
        movq %rax,%es
        movq %rax,%fs
        movq %rax,%gs
        movq %rax,%ss

        /*
         * Set cr0 to a known state:
         *  - Paging enabled
         *  - Alignment check disabled
         *  - Write protect disabled
         *  - No task switch
         *  - Don't do FP software emulation.
         *  - Proctected mode enabled
         */
        movq	%cr0, %rax
        andq	$~(X86_CR0_AM | X86_CR0_WP | X86_CR0_TS | X86_CR0_EM |  X86_CR0_MP | X86_CR0_NE), %rax
        orl	$(X86_CR0_PG | X86_CR0_PE), %eax
        movq	%rax, %cr0

        /*
         * The main loop that copies the kernel from the
         * temporary pages to the final kernel destnation.
         */
        cld
        /* Saved list of source pages. */
        movq 0(%rsp), %rbx
        /*
         * This is the initial dest page.
         * @ KERNBASE + 0x200000
         * Kernel is contigious in memory.
         */
        movq 8(%rsp), %rdi
0:	/* Top -- read another word for the indirection page. */
        movq	(%rbx), %rcx

        addq	$8, %rbx
        testq	$0x1,   %rcx  /* Is it a destination page? */
        jz	1f
        movq	%rcx,	%rdi
        andq	$0xFFFFFFFFfffff000, %rdi
        jmp     0b
1:
        testq	$0x2,	%rcx  /* Is it an indirection page? */
        jz	1f
        movq	%rcx,	%rbx
        andq	$0xFFFFFFFFfffff000, %rbx
        jmp     0b
1:
        testq   $0x4,   %rcx /* Is it the done indicator? */
        jz      1f
        jmp     2f
1:
        testq   $0x8,   %rcx /* Is it the source indicator? */
        jz      0b           /* Ignore it otherwise. */
        movq    %rcx,   %rsi /* For every source page do a copy. */
        andq    $0xfffffffffffff000, %rsi
        movq    $512, %rcx
        rep
        movsq
        jmp     0b
2:
        /*
         * Set all of the registers to known values.
         * Leave %rsp alone.
         */
        xorq	%rax, %rax
        xorq	%rbx, %rbx
        xorq    %rcx, %rcx
        xorq    %rdx, %rdx
        xorq    %rsi, %rsi
        xorq    %rdi, %rdi
        xorq    %rbp, %rbp

        pushq	16(%r9)	/* physfree */
        movq	8(%r9), %rax	/* modulep */
        salq	$32, %rax
        pushq	%rax

        pushq $0x8
        pushq	48(%r9)	/* entry # kernel entry pt */
        lretq
relocate_kernel_end:
        .globl relocate_kernel_size
relocate_kernel_size:
        .long relocate_kernel_end - relocate_kernel

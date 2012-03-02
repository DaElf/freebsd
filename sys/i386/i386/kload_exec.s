	/* Must be relocatable PIC code callable as a C function, that once
	 * it starts can not use the previous processes stack.
	 *
	 */
#include "assym.s"

#define	CR0_PG		0x80000000 /* PaGing enable */

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
	// first install the new page table
	movl	16(%ebx), %esi // page table
	movl 	20(%ebx), %edi  // address of control_page with new PT
	movl	%esi, %cr3

	/*
	 * Set cr4 to a known state:
	 *  - page size extensions
	 */
	movl	$(X86_CR4_PSE), %esi
	movl	%esi, %cr4


	// then move the stack to the end of control page
	lea 4096(%ebx), %esp

	// now save stuff onto the new stack
	pushl %edi	// control page new PT
	pushl %eax	// arg 3 code page
	pushl %edx	// arg 2 kern base
	pushl %ecx	// arg 1 va_list

	/* zero out flags, and disable interrupts */
	pushl $0
	popfl
	cli

	/* install simple gdt */
	movl	12(%edi), %esi	// gdt
	lgdt	(%esi)
	movl	26(%edi), %esi
	lidt	(%esi) 	// null idt
	// now move to the code page
	
	addl $(identity_mapped - relocate_kernel), %eax
	/* offset of code segment in new gdt */
	pushl $0x08
	pushl %eax
	// jump to this spot in the new page
	lretl
identity_mapped:

	movl $0x10,%eax
	movl %eax,%ds
	movl %eax,%es
	movl %eax,%fs
	movl %eax,%gs
	movl %eax,%ss

	/*
	 * Set cr0 to a known state:
	 *  - Paging enabled
	 *  - Alignment check disabled
	 *  - Write protect disabled
	 *  - No task switch
	 *  - Don't do FP software emulation.
	 *  - Proctected mode enabled
	 */
	movl	%cr0, %eax

	andl	$~(X86_CR0_AM | X86_CR0_WP | X86_CR0_TS | X86_CR0_EM |  X86_CR0_MP | X86_CR0_NE | X86_CR0_PG | X86_CR0_PE), %eax
	orl	$(X86_CR0_PG | X86_CR0_PE), %eax
	movl	%eax, %cr0

	/* Do the copies */
	cld
	/* saved list of source pages */
	movl 0(%esp), %ebx
	/* the initial dest page
	* this is KERNBASE + 0x400000 start of first extended page
	* @2m for 64bit and PAE(not supported) @4M for i386
	* kernel is contiguous in memory
	*/
	movl	4(%esp), %edi

0:	/* top, read another word for the indirection page */
	movl    (%ebx), %ecx

	addl	$4, %ebx
	testl	$0x1,   %ecx  /* is it a destination page */
	jz	1f
	movl	%ecx,	%edi
	andl	$0xfffff000, %edi
	jmp     0b
1:
	testl	$0x2,	%ecx  /* is it an indirection page */
	jz	1f
	movl	%ecx,	%ebx
	andl	$0xfffff000, %ebx
	jmp     0b
1:
	testl   $0x4,   %ecx /* is it the done indicator */
	jz      1f
	jmp     2f
1:
	testl   $0x8,   %ecx /* is it the source indicator */
	jz      0b	     /* Ignore it otherwise */
	movl    %ecx,   %esi /* For every source page do a copy */
	andl    $0xfffff000, %esi
	movl    $1024, %ecx
	rep
	movsl
	jmp     0b

2:
	/* set all of the registers to known values */
	/* leave %esp alone */
	
	xorl	%eax, %eax
	xorl	%ebx, %ebx
	xorl    %ecx, %ecx
	xorl    %edx, %edx
	xorl    %esi, %esi
	xorl    %edi, %edi
	xorl    %ebp, %ebp

	movl 	12(%esp), %ebx  /* address of control_page with new PT */
	pushl	8(%ebx)		/* physfree */
	pushl	4(%ebx)		/* modulep */
	pushl	36(%ebx)	/* bootinfop */
	pushl	$0
	pushl	$0
	pushl	$0
	pushl	$0		/* bootdev *unused* */
	pushl	32(%ebx)	/* boothowto */
	pushl	$0xdeadbeef	/* push bogus no-zero return address */
				/* recover_bootinfo keys off of this so must not be 0 */

	pushl $0x8
	pushl 24(%ebx)		/* entry # kernel entry pt */
	lretl
	ret
relocate_kernel_end:

	.globl relocate_kernel_size
relocate_kernel_size:
	.long relocate_kernel_end - relocate_kernel

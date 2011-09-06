/* convert this to 64bit */
	/* Must be relocatable PIC code callable as a C function, that once
	 * it starts can not use the previous processes stack.
	 *
	 */
	.globl relocate_kernel
relocate_kernel:
	/* read the arguments and say goodbye to the stack */
//	movq  8(%rsp), %rbx /* indirection_page */
	// This will blast the stack ... set the base ptr to the location of the kernel start */
//	movq  10(%rsp), %rbp /* reboot_code_buffer */
	movq  18(%rsp), %rdx /* start address */

	movq $0xF, %rax
	ret
	/* zero out flags */
	pushq $0
	popfq
	cli

	/* set a new stack at the bottom of our page... */
	lea   4096(%rbp), %rsp

	/* store the parameters back on the stack */
	pushq   %rdx /* store the start address */

	/* Turn off paging, leave protection turned on */
	movq %cr0, %rax	/* Turn off paging (bit 31 in CR0) */
	andq $0x7FFFFFFF, %rax
	movq %rax, %cr0
	jmp 1f
1:	

	/* Flush the TLB (needed?) */
	xorq %rax, %rax
	movq %rax, %cr3

	/* Do the copies */
	cld
0:	/* top, read another word for the indirection page */
	movq    %rbx, %rcx
	movq	(%rbx), %rcx
	addq	$4, %rbx
	testq	$0x1,   %rcx  /* is it a destination page */
	jz	1f
	movq	%rcx,	%rdi
	andq	$0xFFFFFFFFfffff000, %rdi
	jmp     0b
1:
	testq	$0x2,	%rcx  /* is it an indirection page */
	jz	1f
	movq	%rcx,	%rbx
	andq	$0xFFFFFFFFfffff000, %rbx
	jmp     0b
1:
	testq   $0x4,   %rcx /* is it the done indicator */
	jz      1f
	jmp     2f
1:
	testq   $0x8,   %rcx /* is it the source indicator */
	jz      0b	     /* Ignore it otherwise */
	movq    %rcx,   %rsi /* For every source page do a copy */
	andq    $0xfffffffffffff000, %rsi

	movq    $1024, %rcx
	rep ; movsl
	jmp     0b

2:
	/* set all of the registers to known values */
	/* leave %rsp alone */
	
	xorq	%rax, %rax
	xorq	%rbx, %rbx
	xorq    %rcx, %rcx
	xorq    %rdx, %rdx
	xorq    %rsi, %rsi
	xorq    %rdi, %rdi
	xorq    %rbp, %rbp
	ret
relocate_kernel_end:

	.globl relocate_kernel_size
relocate_kernel_size:	
	.long relocate_kernel_end - relocate_kernel


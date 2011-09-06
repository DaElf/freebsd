	/* Must be relocatable PIC code callable as a C function, that once
	 * it starts can not use the previous processes stack.
	 *
	 */
	.globl relocate_new_kernel
relocate_new_kernel:
	/* read the arguments and say goodbye to the stack */
	movl  4(%esp), %ebx /* indirection_page */
	movl  8(%esp), %ebp /* reboot_code_buffer */
	movl  12(%esp), %edx /* start address */

	/* zero out flags */
	pushl $0
	popfl
	cli

	/* set a new stack at the bottom of our page... */
	lea   4096(%ebp), %esp

	/* store the parameters back on the stack */
	pushl   %edx /* store the start address */

	/* Turn off paging, leave protection turned on */
	movl %cr0, %eax	/* Turn off paging (bit 31 in CR0) */
	andl $0x7FFFFFFF, %eax
	movl %eax, %cr0
	jmp 1f
1:	

	/* Flush the TLB (needed?) */
	xorl %eax, %eax
	movl %eax, %cr3

	/* Do the copies */
	cld
0:	/* top, read another word for the indirection page */
	movl    %ebx, %ecx
	movl	(%ebx), %ecx
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
	rep ; movsl
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
	ret
relocate_new_kernel_end:

	.globl relocate_new_kernel_size
relocate_new_kernel_size:	
	.long relocate_new_kernel_end - relocate_new_kernel
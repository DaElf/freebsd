	/* Must be relocatable PIC code callable as a C function, that once
	 * it starts can not use the previous processes stack.
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

.macro dumphex val
	pushq %rsi
	movq \val, %rsi
	movl $0, %eax
	call print_hex
	movq $nlrt, %rsi
	movl $0, %eax
	call print_string
	popq %rsi
.endm	


.p2align 4,0x90;
	.globl kernel_jump;
	.type kernel_jump,@function;
kernel_jump:
	
	.globl relocate_kernel
relocate_kernel:
	/* read the arguments and say goodbye to the stack */
//	movq  8(%rsp), %rbx /* indirection_page */
	// This will blast the stack ... set the base ptr to the location of the kernel start */
//	movq  10(%rsp), %rbp /* reboot_code_buffer */
//	movq  18(%rsp), %rdx /* start address */

//	pushq %rbp
//	movq  %rsp, %rbp

	// move the stack to the end of the control page
	
//	lea 4096(%rcx), %rsp
	
	/* jump to identity mapped page */
//	addq	$(identity_mapped - relocate_kernel), %r8
//	pushq	%r8
//	ret

//identity_mapped:
	/* store the start address on the stack */
//	pushq   %rdx

	// first install the new page table
	movq	32(%rcx), %rax // page table
	movq 	40(%rcx), %r9  // address of control_page with new PT
	movq	%rax, %cr3
	

	// then move the stack to the end of control page
	lea 4096(%r9), %rsp

	// now save stuff onto the new stack
	pushq %rcx	// arg 4 control page
	pushq %rdx	// arg 3 code page
	pushq %rsi	// arg 2 kern base
	pushq %rdi	// arg 1 va_list

	/* zero out flags, and disable interrupts */
	pushq $0
	popfq
	cli
	
	/* install simple gdt */
	movq	24(%r9), %rax	// gdt
	lgdt	(%rax)
	// now move to the code page
	// should have been passwd code_page based on new PT
	movq %rdx, %r8
	addq	$(identity_mapped - relocate_kernel), %r8
	/* offset of code segment in new gdt */
	pushq $0x08
	pushq %r8
	// jump to this spot in the new page
	lretq
identity_mapped:


	movq $0x10,%rax
	movq %rax,%ds
	movq %rax,%es
	movq %rax,%fs
	movq %rax,%gs
	movq %rax,%ss
//	# Display a message to say everything is working so far
//	pushq %rdi
//	movq $s_hello2, %rdi
//	call printf
//	popq %rdi


#if 0
	movq	24(%r9), %rax	// gdt
	lgdt	(%rax)

	// now jump the code to use the new gdt segment
	pushq $0x8
	pushq 1f
	lretq
//	ljmp 1f
	nop	
1:
	// we just loaded a bogus data segment so se can't set any of the
	// data segment register
	movq $0x10,%rax
	movq %rax,%ds
	movq %rax,%es
	movq %rax,%fs
	movq %rax,%gs
	movq %rax,%ss
#endif
#if 1
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
	andq	$~(X86_CR0_AM | X86_CR0_WP | X86_CR0_TS | X86_CR0_EM), %rax
	orl	$(X86_CR0_PG | X86_CR0_PE), %eax
	movq	%rax, %cr0

#endif
	
	/* Do the copies */
	cld
	/* saved list of source pages */
	movq 0(%rsp), %rbx
	/* the initial dest page
	* this is KERNBASE + 0x200000
	* kernel is contigious in memory
	*/
	movq 8(%rsp), %rdi
0:	/* top, read another word for the indirection page */
	movq	(%rbx), %rcx
	
	addq	$8, %rbx
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
	movq    $512, %rcx
	rep
	movsq

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

	pushq	16(%r9)		// physfree
	movq	8(%r9), %rax	//modulep
	salq	$32, %rax
	pushq	%rax

	pushq $0x8
	pushq $0xffffffff8026fc60
	lretq

/* print to serial port */
/* borrowed from kexec-tools */
print_string:
	.code64
//	pushq	%rbp
//	movq	%rsp, %rbp
//	pushq	%rsi
//	movq	8(%rbp), %rsi
	xorq	%rax, %rax
print_string.1:	
	lodsb %ds:(%rsi), %al
	testb	$0xff, %al
	jz	print_string.2
	call	print_char
	jmp	print_string.1
print_string.2:
//	popq	%rsi
//	popq	%rbp
	ret


print_hex:
	.code64
//	pushq	%rbp
//	movq	%rsp, %rbp
	pushq	%rcx
	movb	$64, %cl
print_hex.1:	
//	movl	8(%ebp), %eax
	movq	%rsi, %rax
	subb	$4, %cl
	shrq	%cl, %rax
	andb	$0x0f, %al
	cmpb	$9, %al
	ja	print_hex.2
	addb	$'0', %al
	jmp	print_hex.3
print_hex.2:	
	addb	$'A' - 10, %al
print_hex.3:
	call	print_char
	testb	%cl, %cl
	jnz	print_hex.1

	//popl	%ebp
	popq	%rcx
	ret

print_char:
.code64
	# The character to print is in al 
	call serial_print_char
	retq


#define TTYS0_BASE	0x3f8
#define TTYS0_RBR	(TTYS0_BASE + 0x00)
#define TTYS0_TBR	(TTYS0_BASE + 0x00)
#define TTYS0_LSR	(TTYS0_BASE + 0x05)
serial_print_char:
	.code64
	# The character to print is in al 
	pushq	%rax
	pushq	%rdx
	
	# Wait until the serial port is ready to receive characters 
serial_print_char.1:
	movq	$TTYS0_LSR, %rdx
	inb	%dx, %al
	testb	$0x20, %al
	jz	serial_print_char.1

	# Output the character 
	movq	$TTYS0_TBR, %rdx
	movb	0(%rsp), %al
	outb	%al, %dx

	# Wait until the serial port has transmitted the character 
serial_print_char.2:
	movq	$TTYS0_LSR, %rdx
	inb	%dx, %al
	testb	$0x40, %al
	jz	serial_print_char.2

	popq	%rdx
	# Restore %rax 
	popq	%rax
	# Return to caller 
	ret

	
s_hello:
	.ascii	"Hello from kernel kexec string1 \r\n"


s_hello2:
	.string "Hello from kernel kexec string2 \r\n"
	.text
	.p2align 4,,15
nlrt:
	.string "\r\n"
	.text
	.p2align 4,,15

s_src:
	.string "Source Page\r\n"
	.text
	.p2align 4,,15
s_ind:
	.string "Indirect Page\r\n"
	.text
	.p2align 4,,15
s_done:
	.string "Done Page\r\n"
	.text
	.p2align 4,,15

hello_hex:
        .string "Hello world 0x%lx\n"
        .text
	.p2align 4,,15
	
relocate_kernel_end:

	.globl relocate_kernel_size
relocate_kernel_size:	
	.long relocate_kernel_end - relocate_kernel

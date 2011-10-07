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

	dumphex %rdi // arg 1 GDT
	dumphex %rsi // arg 2 page table

	cli

	/* Set %cr3 for PT4 */
	movq	%rsi, %rax
	movq	%rax, %cr3
	
	lgdt	(%rdi)

	jmp 1f
	nop	
1:
#if 1
	// we just loaded a bogus data segment so se can't set any of the
	// data segment register
	movq $0x10,%rax
	movq %rax,%ds
	movq %rax,%es
	movq %rax,%fs
	movq %rax,%gs
	movq %rax,%ss
#endif
	popq	%rax
	/* reload code selector by turning return into intersegmental return */
//	pushq  $0xe19000
//	movl $0xe18000, %eax  // modulep
	pushq %rsi
	movq %rdi, %rax
	salq $32, %rax
	pushq %rax

	pushq $0x8
	pushq $kern_enter
//	jmp     0xffffffff8026f950
//	ljmp  0x8,kern_enter
	lretq
.size kernel_jump, . - kernel_jump 

.p2align 4,0x90;
	.globl kernel_jump_simple;
	.type kernel_jump_simple,@function;
kernel_jump_simple:

	dumphex %rdi // arg 1
	dumphex %rsi // arg 2
	dumphex %rdx
	dumphex %rcx

	cli

	/* Set %cr3 for PT4 */
//	movq	%rsi, %rax
//	movq	%rax, %cr3
	
//	lgdt	(%rdi)

//	jmp 1f
//	nop	
1:
#if 0
	// we just loaded a bogus data segment so se can't set any of the
	// data segment register
	movq $0x10,%rax
	movq %rax,%ds
	movq %rax,%es
	movq %rax,%fs
	movq %rax,%gs
	movq %rax,%ss
#endif
	popq	%rax
	/* reload code selector by turning return into intersegmental return */
//	pushq  $0xc71000
//	movl $0xc70000, %eax  // modulep
	pushq %rsi // physfree
	movq %rdi, %rax //modulep
	salq $32, %rax
	pushq %rax

	pushq $0x20
	pushq $kern_enter
//	jmp     0xffffffff8026f950
//	ljmp  0x8,kern_enter
	lretq
.size kernel_jump, . - kernel_jump 
	
	.globl relocate_kernel
relocate_kernel:
	/* read the arguments and say goodbye to the stack */
//	movq  8(%rsp), %rbx /* indirection_page */
	// This will blast the stack ... set the base ptr to the location of the kernel start */
//	movq  10(%rsp), %rbp /* reboot_code_buffer */
//	movq  18(%rsp), %rdx /* start address */

	pushq %rbp
	movq  %rsp, %rbp

	pushq %rdi	// arg 1 va_list
	pushq %rdx	// arg 3 code page
	pushq %rsi	// arg 2 kern base
	pushq %rdi	// arg 1 va_list

	# Display a message to say everything is working so far
	pushq %rcx	// arg 4 control page
	pushq %rdi
	movq $s_hello2, %rdi
	call printf
	popq %rdi

#if 0
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
	andq $0xFFFFFFFF7fffffff, %rax
	movq %rax, %cr0
	jmp 1f
1:	

	/* Flush the TLB (needed?) */
	xorq %rax, %rax
	movq %rax, %cr3
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

	//	jmp 0xffffffff8026f950
#endif
	
	/* Do the copies */
	cld
	movq 0(%rsp), %rbx
0:	/* top, read another word for the indirection page */
	movq $s_hello2, %rsi
	movl $0, %eax
	call print_string
	
	movq    $0x1008, %rcx
	dumphex %rcx
	
	movq	(%rbx), %rcx
//	dumphex %rbx
//	dumphex (%rbx)
	dumphex %rcx
	
	addq	$8, %rbx
	testq	$0x1,   %rcx  /* is it a destination page */
	jz	1f
	movq	%rcx,	%rdi
	andq	$0xFFFFFFFFfffff000, %rdi
	jmp     0b
1:
	testq	$0x2,	%rcx  /* is it an indirection page */
	jz	1f
	movq $s_ind, %rsi
	movl $0, %eax
	call print_string
	movq	%rcx,	%rbx
	andq	$0xFFFFFFFFfffff000, %rbx
	jmp     0b
1:
	testq   $0x4,   %rcx /* is it the done indicator */
	jz      1f
	movq $s_done, %rsi
	movl $0, %eax
	call print_string
	jmp     2f
1:
	testq   $0x8,   %rcx /* is it the source indicator */
	jz      0b	     /* Ignore it otherwise */
	movq $s_src, %rsi
	movl $0, %eax
	call print_string
	movq    %rcx,   %rsi /* For every source page do a copy */
	andq    $0xfffffffffffff000, %rsi

#if 1	
	movq    $512, %rcx
	rep ; movsq
#endif
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

	pushq $0x20
	pushq $0xffffffff8026fc90
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

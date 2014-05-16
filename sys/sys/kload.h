/*
 * Copyright (c) 2011 - 2016
 *	Russell Cattelan Digital Elves LLC
 * Copyright (c) 2012 - 2015
 *	EMC Corp / Isilon Systems Division  All rights reserved.
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

#ifndef __KLOAD_H__
#define __KLOAD_H__

#include <sys/param.h>
#include <sys/types.h>

#include <machine/atomic.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

#define KLOAD_LOAD		 0
#define KLOAD_REBOOT		(1 << 0 )
#define KLOAD_EXEC		(1 << 1 )
#define KLOAD_SEGMENTS		1

struct kload_segment {
	void		       *k_buf;
	size_t			k_memsz;
	unsigned long	       *k_pages;
	unsigned long		k_seg_start;
};

struct kload {
	struct kload_segment	khdr[KLOAD_SEGMENTS];
	int			num_hdrs;
	unsigned long		k_entry_pt;
	unsigned int		k_modulep;
	unsigned int		k_physfree;
};

#define KLOAD_DESTINATION  0x1
#define KLOAD_INDIRECT     0x2
#define KLOAD_DONE         0x4
#define KLOAD_SOURCE       0x8

struct kload_items {
	unsigned long head;
	vm_offset_t head_va;
	unsigned long *last_item;
	unsigned long *item;
	int i_count;
	unsigned long flags;  /* not used yet */
};

struct kload_args {
	const struct kload * kld;
	size_t buflen;
	u_int32_t flags;
};

/*
 * defined in <arch>/kload.c
 */
pt_entry_t * kload_build_page_table(void);
void setup_freebsd_gdt(uint64_t *);
void kload_module_shutdown(void);

/*
 * defined in <arch>/kload_exec.S
 */
unsigned long relocate_kernel(unsigned long indirection_page,
    unsigned long page_list, unsigned long code_page,
    unsigned long control_page);
extern int relocate_kernel_size;

#endif

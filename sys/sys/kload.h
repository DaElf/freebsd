/*
 * Russell Cattelan
 *	Digital Elves Inc 2011 - 2012
 * Copyright (c) 2011 - 2012
 *	Isilon Systems, LLC.  All rights reserved.
 */

#ifndef __KLOAD_H__
#define __KLOAD_H__

#include <sys/param.h>
#include <sys/types.h>

#include <vm/vm.h>
#include <vm/vm_page.h>

#define	KLOAD_LOAD	0
#define	KLOAD_REBOOT	(1 << 0)
#define	KLOAD_EXEC	(1 << 1)

typedef size_t k_size_t;
struct kload_segment {
	void		       *k_buf;
	size_t			k_memsz;
	size_t		       *k_pages;
	size_t			k_seg_start;
};

struct kload {
	struct kload_segment	khdr[10];
	int			num_hdrs;
	size_t			k_entry_pt;
	/*
	 * the loader runs as 32 bit so it pushes
	 * modulep and physfree onto the stack as 32bit
	 * values. btext expecting 32 bit stack values
	 */
	uint32_t		k_modulep;
	uint32_t		k_physfree;
};

//typedef u_long kload_item_t;
#define	KLOAD_DESTINATION	0x1
#define	KLOAD_INDIRECT		0x2
#define	KLOAD_DONE		0x4
#define	KLOAD_SOURCE		0x8

struct kload_items {
	unsigned long	head;
	vm_offset_t	head_va;
	size_t	       *last_item;
	size_t	       *item;
	int		i_count;
	size_t		flags;  /* not used yet */
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
k_size_t relocate_kernel(k_size_t indirection_page,
			      k_size_t page_list,
			      k_size_t code_page,
			      k_size_t control_page);
extern int relocate_kernel_size;

#endif

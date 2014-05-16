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

#include <sys/kload.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <vm/vm_param.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>

#define	GUEST_NULL_SEL		0
#define	GUEST_CODE_SEL		1
#define	GUEST_DATA_SEL		2

/*  Set up the GDT the same as what the boot loader
    one noteable change is turn on write access to
    the data segment so we can write to it during
    final relocate_kernel phase
 sys/boot/i386/libi386/amd64_tramp.S
   gdt:
	.long	0			# null descriptor
	.long	0
	.long	0x00000000		# %cs
	.long	0x00209800
	.long	0x00000000		# %ds
	.long	0x00008000
*/

void
setup_freebsd_gdt(uint64_t *gdtr)
{
	gdtr[GUEST_NULL_SEL] = 0x0000000000000000;
	gdtr[GUEST_CODE_SEL] = 0x0020980000000000;
	gdtr[GUEST_DATA_SEL] = 0x0000920000000000;
}

pt_entry_t *
kload_build_page_table(void)
{
	pt_entry_t *PT4;
	pt_entry_t *PT3;
	pt_entry_t *PT2;
	int i;
	pt_entry_t va;

	va = kmem_malloc(kernel_arena,  PAGE_SIZE * 3, M_ZERO | M_WAITOK);
	PT4 = (pt_entry_t *)va;
	PT3 = (pt_entry_t *)(PT4 + (PAGE_SIZE / sizeof(unsigned long)));
	PT2 = (pt_entry_t *)(PT3 + (PAGE_SIZE / sizeof(unsigned long)));

	if (bootverbose)
		printf("%s PT4 0x%lx (0x%lx) PT3 0x%lx (0x%lx) "
		    "PT2 0x%lx (0x%lx)\n",
		    __func__,
		    (unsigned long)PT4, (unsigned long)vtophys(PT4),
		    (unsigned long)PT3, (unsigned long)vtophys(PT3),
		    (unsigned long)PT2, (unsigned long)vtophys(PT2));

	/*
	 * The following section is a direct copy of
	 * head/src/sys/boot/i386/libi386/elf64_freebsd.c:92 at r236688
	 */

	bzero(PT4, PAGE_SIZE);
	bzero(PT3, PAGE_SIZE);
	bzero(PT2, PAGE_SIZE);

	/*
	 * This is kinda brutal, but every single 1GB VM memory segment points
	 * to the same first 1GB of physical memory.  But it is more than
	 * adequate.
	 */
	for (i = 0; i < 512; i++) {
		/*
		 * Each slot of the level 4 pages points to the
		 * same level 3 page
		 */
		PT4[i] = (pt_entry_t)(vtophys(PT3));
		PT4[i] |= PG_V | PG_RW | PG_U;

		/*
		 * Each slot of the level 3 pages points to the
		 * same level 2 page
		 */
		PT3[i] = (pt_entry_t)(vtophys(PT2));
		PT3[i] |= PG_V | PG_RW | PG_U;

		/* The level 2 page slots are mapped with 2MB pages for 1GB. */
		PT2[i] = i * (2 * 1024 * 1024);
		PT2[i] |= PG_V | PG_RW | PG_PS | PG_U;
	}
	return ((pt_entry_t *)vtophys(PT4));
}

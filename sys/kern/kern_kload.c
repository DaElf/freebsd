/*
 * Copyright (c) 2011 - 2016
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
#include <sys/param.h>
#include <sys/bus.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/kload.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/reboot.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/syscall.h>

#include <machine/smp.h>
//#include <machine/intr_machdep.h>
//#include <machine/apicvar.h>
//#include <machine/segments.h>

#include <vm/vm_param.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_map.h>


static struct kload_items *k_items = NULL;
static MALLOC_DEFINE(M_KLOAD, "kload_items", "kload items");
static int kload_ready = 0;
static int kload_prealloc = 0;
TUNABLE_INT("kern.kload_prealloc", &kload_prealloc);

static vm_offset_t kload_image_va = 0;
/*
 * Warning this is somewhat arbitrary, but should go
 * away once the allocate delays in kmem_alloc_attr are
 * fixed.
 */
#define	IMAGE_PREALLOC_MAX	(48 * 1024 * 1024)

static void kload_init(void);
SYSINIT(kload_mem, SI_SUB_DRIVERS, SI_ORDER_ANY, kload_init, NULL);

static int kload_copyin_segment(struct kload_segment *, int);
static int kload_add_page(struct kload_items *, unsigned long);
static void kload_shutdown_final(void *, int);
static struct region_descriptor *mygdt;
static	vm_offset_t control_page;
static	vm_offset_t code_page;
static	void *gdt_desc;
pt_entry_t *kload_pgtbl = NULL; /* used as a test */
static unsigned long max_addr = 0 , min_addr = 0;

#define	GIGMASK		(~((1<<30)-1))
#define	ONEGIG			(1<<30)
#define	GUEST_GDTR_LIMIT	(3 * 8 - 1)

extern char kernphys[];
#define	KLOADBASE		KERNBASE

static void
update_max_min(vm_offset_t addr, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (vtophys(addr + (i * PAGE_SIZE)) < min_addr)
			min_addr = vtophys(addr + (i * PAGE_SIZE));
		if (vtophys(addr + (i * PAGE_SIZE)) > max_addr)
			max_addr = vtophys(addr + (i * PAGE_SIZE));
	}
}

static vm_offset_t
kload_kmem_alloc(vm_size_t size)
{
	vm_offset_t va;
	int num_pages;

	va = kmem_alloc_attr(kernel_arena, size,
	    M_WAITOK | M_ZERO,
	    0, (1 << 30) /* 1Gig limit */,
	    VM_MEMATTR_WRITE_COMBINING);

	if (va) {
		num_pages = roundup2(size,PAGE_SIZE) >> PAGE_SHIFT;
		update_max_min(va, num_pages);
	}

	return (va);
}

struct kload_cpage {
	unsigned long kcp_magic;	/* 0 */
	unsigned long kcp_modulep;	/* 1 */
	unsigned long kcp_physfree;	/* 2 */
	unsigned long kcp_gdt;		/* 3 */
	unsigned long kcp_pgtbl;	/* 4 */
	unsigned long kcp_cp;		/* 5 */
	unsigned long kcp_entry_pt;	/* 6 */
	unsigned long kcp_idt;		/* 7 */
} __packed;

static int
kload_add_page(struct kload_items *items, unsigned long item_m)
{
	vm_paddr_t phys;
	unsigned long va;

	if (*items->item != 0) {
		printf(" item != 0 0x%lx\n", *items->item);
		items->item++;
		items->i_count--;
	}

	if ((items->item == items->last_item) || (items->i_count == 0)) {
		/* out of space in current page grab a new one */
		va = (unsigned long)kload_kmem_alloc(PAGE_SIZE);
		if (items->head_va == 0)
			items->head_va = va;

		phys = vtophys(va);
		/* store the address of indrect page */
		*items->item = (unsigned long)
		    (vtophys(va) + KLOADBASE) | KLOAD_INDIRECT;
		items->item = (unsigned long *)va;
		/* ok now move to new page to start storing address */
		items->last_item = (unsigned long *)va +
		    ((PAGE_SIZE/sizeof(unsigned long)) - 1);
		items->i_count = ((PAGE_SIZE/sizeof(unsigned long)) - 1);
	}
	*items->item = item_m;
	items->item++;
	items->i_count--;

	return (0);
}

static void
kload_init(void)
{
	int size;

	if (kload_prealloc > 0) {
		size = min((kload_prealloc * 1024 * 1024), IMAGE_PREALLOC_MAX);
	kload_image_va = kload_kmem_alloc(size);
		printf("%s: preallocated %dMB\n", __func__, kload_prealloc);
		kload_prealloc = size; /* re-use for copy in check */
	} else {
		printf("%s: has not preallocated temporary space\n", __func__);
	}

}

int
kload_copyin_segment(struct kload_segment *khdr, int seg)
{
	int i;
	int num_pages;
	int error = 0;
	vm_offset_t va = kload_image_va;

	num_pages = roundup2(khdr->k_memsz,PAGE_SIZE) >> PAGE_SHIFT;

	/* check to make sure the preallocate space is beg enough */
	if (va && ((num_pages * PAGE_SIZE) > kload_prealloc)) {
		printf("%s size over prealloc size %d need %d\n", __func__,
		       kload_prealloc, num_pages * PAGE_SIZE);
		kmem_free(kernel_arena, va, kload_prealloc);
		va = 0;
	}

	if (va == 0) {
		va = kload_kmem_alloc(num_pages * PAGE_SIZE);
		if (va == 0)
			return (ENOMEM);
	}

	/*  need to set up a START dst page */
	for (i = 0; i < num_pages; i++) {
		kload_add_page(k_items,
		    (vtophys(va + (i * PAGE_SIZE)) + KLOADBASE) | KLOAD_SOURCE);
	}
	printf("%s starting copyin... ", __func__);
	*k_items->item = KLOAD_DONE;
	if ((error = copyin(khdr->k_buf, (void *)va, khdr->k_memsz)) != 0)
		return (error);
	printf("copied %d bytes to va %p done marker at %p\n",
	       (int)khdr->k_memsz, (void *)va, &k_items->item );

	return (error);
}

static int
sys_kload(struct thread *td, struct kload_args *uap)
{
	struct region_descriptor *null_idt;
	struct kload_cpage *k_cpage;
	struct kload kld;
	int error = 0;
	int i;
	size_t bufsize = uap->buflen;

	error = priv_check(td, PRIV_REBOOT);
	if (error)
		return (error);

	/*
	 * Hook into the shutdown/reboot path so
	 * we end up here before cpu reset.
	 */
	EVENTHANDLER_REGISTER(shutdown_final, kload_shutdown_final,
	    NULL, SHUTDOWN_PRI_KLOAD);

	max_addr = 0;
	min_addr = ~0UL;

	if (bufsize != sizeof(struct kload)) {
		printf("size does not match bufsize: %jd kload: %jd\n",
		       (uintmax_t)bufsize,
		       (uintmax_t)sizeof(struct kload));
		return (error);
	}
	if ((error = copyin(uap->kld, &kld, bufsize)) != 0)
		return (error);

	if (k_items == NULL) {
		if((k_items = malloc(sizeof(struct kload_items),
			    M_KLOAD, M_WAITOK | M_ZERO)) == NULL)
			return (ENOMEM);

		k_items->head = 0;
		k_items->head_va = 0;
		k_items->item = &k_items->head;
		k_items->last_item = &k_items->head;
	}

	control_page = kload_kmem_alloc(PAGE_SIZE * 2);
	if (control_page == 0)
		return (ENOMEM);
	k_cpage = (struct kload_cpage *)control_page;
	code_page = control_page + PAGE_SIZE;

	printf("copy from %p kernel_kump to 0x%lx size %d\n",
	       relocate_kernel, (unsigned long)code_page, relocate_kernel_size);
	memset((void *)control_page, 0, PAGE_SIZE * 2);
	memcpy((void *)code_page, relocate_kernel, relocate_kernel_size);

	k_cpage->kcp_magic = 0xC0DE;
	k_cpage->kcp_modulep = kld.k_modulep;
	k_cpage->kcp_physfree = kld.k_physfree;

	mygdt = (struct region_descriptor *)kload_kmem_alloc(PAGE_SIZE);
	if (mygdt == NULL)
		return (ENOMEM);
	k_cpage->kcp_gdt = (unsigned long)vtophys(mygdt) + KLOADBASE;

	gdt_desc = (char *)mygdt + sizeof(struct region_descriptor);
	setup_freebsd_gdt(gdt_desc);
	mygdt->rd_limit = GUEST_GDTR_LIMIT;
	mygdt->rd_base = (unsigned long)(vtophys(gdt_desc) + KLOADBASE);

	/*
	 * we pass the virt addr of control_page but we need
	 * new virt addr as well
	 */
	k_cpage->kcp_cp = (unsigned long)(vtophys(control_page) + KLOADBASE);
	k_cpage->kcp_entry_pt = kld.k_entry_pt;

	/* 10 segments should be more than enough */
	for (i = 0 ; (i < kld.num_hdrs && i <= 10); i++) {
		error = kload_copyin_segment(&kld.khdr[i], i);
		if (error != 0)
			return (error);
	}

	null_idt = (struct region_descriptor*)
	    kload_kmem_alloc(PAGE_SIZE);
	if (null_idt == NULL)
		return (ENOMEM);
	k_cpage->kcp_idt = (unsigned long)vtophys(null_idt) + KLOADBASE;
	/* Wipe the IDT. */
	null_idt->rd_limit = 0;
	null_idt->rd_base = 0;
	/*
	 * This must be built after all other allocations so it can
	 * build a page table entry based on min max addresses
	 */
	/* returns new page table phys addr */
	kload_pgtbl = kload_build_page_table();
	if (kload_pgtbl == NULL)
		return (ENOMEM);
	k_cpage->kcp_pgtbl = (unsigned long)kload_pgtbl;

	/*
	 * We could simply not install the handler and never
	 * hit kload_shutdown_final. But this way we can log
	 * the fact that we had a failed kload so allow the
	 * function to be called, but flagged not ready.
	 */
	kload_ready = 1;

	if (bootverbose)
		printf("%s:\n\t"
		       "head_va         0x%lx (phys 0x%lx)\n\t"
		       "kernbase        0x%lx\n\t"
		       "code_page       0x%lx (phys 0x%lx)\n\t"
		       "control_page    0x%lx (phys 0x%lx)\n\t"
		       "gdt             0x%lx (phys 0x%lx)\n\t"
		       "idt             0x%lx (phys 0x%lx)\n\t"
		       "k_entry_pt      0x%lx\n\t"
		       "pgtbl                              (phys 0x%lx)\n\t"
		       "max_addr                           (phys 0x%lx)\n\t"
		       "min_addr                           (phys 0x%lx)\n\t"
		       "modulep                            (phys 0x%lx)\n\t"
		       "physfree                           (phys 0x%lx)\n",
		       __func__,
		       (unsigned long)k_items->head_va,
		       (unsigned long)vtophys(k_items->head_va),
		       (unsigned long)(KERNBASE + (vm_paddr_t)kernphys),
		       (unsigned long)(control_page + PAGE_SIZE),
		       (unsigned long)vtophys(control_page + PAGE_SIZE),
		       (unsigned long)control_page,
		       (unsigned long)vtophys(control_page),
		       (unsigned long)mygdt,(unsigned long)vtophys(mygdt),
		       (unsigned long)null_idt,(unsigned long)vtophys(null_idt),
		       (unsigned long)kld.k_entry_pt,
		       (unsigned long)kload_pgtbl,
		       (unsigned long)max_addr,
		       (unsigned long)min_addr,
		       (unsigned long)kld.k_modulep,
		       (unsigned long)kld.k_physfree);

	if(!(uap->flags & (KLOAD_EXEC | KLOAD_REBOOT)))
		goto just_load;
#if defined(SMP)
	/*
	 * Bind us to CPU 0 so that all shutdown code runs there.  Some
	 * systems don't shutdown properly (i.e., ACPI power off) if we
	 * run on another processor.
	 */
	printf("Binding process to cpu 0\n");
	thread_lock(curthread);
	sched_bind(curthread, 0);
	thread_unlock(curthread);
	KASSERT(PCPU_GET(cpuid) == 0, ("%s: not running on cpu 0", __func__));
#endif
	if(uap->flags & KLOAD_REBOOT) {
		mtx_lock(&Giant);
		/* Do we need to implement the reboot howto flags? */
		kern_reboot(0);
		/* should not return */
		mtx_unlock(&Giant);
	}
	/*
	 * The reboot code will do a module shutdown so it is not
	 * part of kload_shutdown_final but it needs to happen.
	 * So in the case of the exec flag being passed run it here.
	 */
	if (bootverbose)
		printf("%s: module_shutdown\n", __func__);
	module_shutdown(NULL, 0);
	kload_shutdown_final(NULL, 0);
just_load:
	printf("%s: Kernel image loaded waiting for reboot\n", __func__);
	return (0);
}

static void
kload_shutdown_final(void *arg, int howto)
{
	int ret;
	cpuset_t map;

	printf("%s: arg %p howto 0x%x\n", __func__, arg, howto);

	if (howto & RB_ABORT_KLOAD) {
		printf("%s: not a kload reboot\n", __func__);
		return;
	}
	/* Just to make sure we are on cpu 0 */
	KASSERT(PCPU_GET(cpuid) == 0, ("%s: not running on cpu 0", __func__));
	if (kload_ready) {
		printf("%s: suspend APs\n", __func__);
		map = all_cpus;
		/* we should be bound to cpu 0 at this point */
		printf("%s: cpuid %d\n", __func__, PCPU_GET(cpuid));
		CPU_CLR(PCPU_GET(cpuid), &map);
		CPU_NAND(&map, &stopped_cpus);
		if (!CPU_EMPTY(&map)) {
			printf("cpu_reset: Stopping other CPUs\n");
			kload_suspend_cpus(map);
		}

		if (bootverbose)
			printf("%s: clear all handlers\n", __func__);
		intr_clear_all_handlers();

		if (bootverbose)
			printf("%s: loapic_clear_lapic\n", __func__);
		lapic_clear_lapic(1);

		intr_suspend();

		if (bootverbose)
			printf("%s: disable_interrupts cpuid %d\n",
			    __func__, PCPU_GET(cpuid));
		disable_intr();

		printf("calling relocate_kernel\n");
		ret = relocate_kernel(vtophys(k_items->head_va) + KLOADBASE,
				      /* dest addr i.e. overwrite existing kernel */
				      KERNBASE + (vm_paddr_t)kernphys,
				      vtophys(code_page) + KLOADBASE,
				      control_page);
		/* currently this will never happen */
		printf("\trelocate_new_kernel returned %d\n",ret);
	} else {
		printf("kload_shutdown_final called without "
		       "a new kernel loaded\n");
	}
}

static int
kload_modload(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		printf("%s: MOD_LOAD\n", __func__);
		break;
	case MOD_UNLOAD:
		printf("%s: MOD_UNLOAD\n", __func__);
		break;
	case MOD_SHUTDOWN:
		break;
	default:
		error = EINVAL;
		break;
	}
	return error;
}

static int offset = NO_SYSCALL;

static struct sysent kload_sysent= {
	3,			/* sy_narg */
	(sy_call_t *)sys_kload	/* sy_call */
};

SYSCALL_MODULE(kload, &offset, &kload_sysent, kload_modload, NULL);
MODULE_VERSION(kload, 1);

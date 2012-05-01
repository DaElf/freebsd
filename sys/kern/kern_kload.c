/*
 * Russell Cattelan
 *	Digital Elves Inc 2011 - 2012
 * Copyright (c) 2011 - 2012
 *	Isilon Systems, LLC.  All rights reserved.
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

#include <machine/intr_machdep.h>
#include <machine/apicvar.h>
#include <machine/segments.h>

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
int kload_ready = 0;

static vm_offset_t kload_image_va = 0;
/*
 * Warning this is somewhat arbitrary, but should go
 * away once the allocate delays in kmem_alloc_attr are
 * fixed.
 */
#define	IMAGE_PREALLOC	(24 * 1024 * 1024)

static void kload_init(void);
SYSINIT(kload_mem, SI_SUB_KMEM, SI_ORDER_ANY, kload_init, NULL);

static int kload_copyin_segment(struct kload_segment *, int);
static int kload_add_page(struct kload_items *, unsigned long);
static void kload_shutdown_final(void *, int);
static struct region_descriptor *mygdt;
static vm_offset_t control_page;
static vm_offset_t code_page;
static void *gdt_desc;
//static pt_entry_t *pgtbl;
pt_entry_t *kload_pgtbl;
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
kload_kmem_alloc(vm_map_t map, vm_size_t size)
{
	vm_offset_t va;
	int num_pages;

	va = kmem_alloc_attr(map, size,
	    M_WAITOK | M_ZERO,
	    0, (1 << 30) /* 1Gig limit */,
	    VM_MEMATTR_WRITE_COMBINING);

	num_pages = roundup2(size,PAGE_SIZE) >> PAGE_SHIFT;
	update_max_min(va, num_pages);

	return va;
}

struct kload_cpage {
	size_t kcp_magic;	/* 0 */
	size_t kcp_modulep;	/* 1 */
	size_t kcp_physfree;	/* 2 */
	size_t kcp_gdt;		/* 3 */
	size_t kcp_pgtbl;	/* 4 */
	size_t kcp_cp;		/* 5 */
	size_t kcp_entry_pt;	/* 6 */
	size_t kcp_idt;		/* 7 */
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

	if (bootverbose)
		printf("%s%d item 0x%lx\n", __func__, __LINE__,
		    (unsigned long)item_m);

	if ((items->item == items->last_item) || (items->i_count == 0)) {
		/* out of space in current page grab a new one */
		va = (unsigned long)kload_kmem_alloc(kernel_map, PAGE_SIZE);
		if (items->head_va == 0)
			items->head_va = va;

		phys = vtophys(va);
		if (0 && bootverbose) {
			printf("%s indirect page item %p va %p stored %p phys %p\n",__func__,
			       (void *)*items->item,
			       (void *)va,
			       (void *)(vtophys(va) + KLOADBASE),
			       (void *)phys );
		}
		/* store the address of indrect page */
		//*items->item = (unsigned long)phys | KLOAD_INDIRECT;
		*items->item = (unsigned long)(vtophys(va) + KLOADBASE) | KLOAD_INDIRECT;
		items->item = (unsigned long *)va;
		/* ok now move to new page to start storing address */
		items->last_item = (unsigned long *)va + ((PAGE_SIZE/sizeof(unsigned long)) - 1);
		items->i_count = ((PAGE_SIZE/sizeof(unsigned long)) - 1);
	}
	*items->item = item_m;
	items->item++;
	items->i_count--;

	return 0;
}

static void
kload_init(void)
{
	int size = IMAGE_PREALLOC;
	kload_image_va = kload_kmem_alloc(kernel_map, size);
	printf("%s 0x%lx preallocated size %d\n",__func__, kload_image_va, size);
}

int
kload_copyin_segment(struct kload_segment *khdr, int seg)
{
	int i;
	int num_pages;
	int error = 0;
	vm_offset_t va = kload_image_va;

	num_pages = roundup2(khdr->k_memsz,PAGE_SIZE) >> PAGE_SHIFT;
	if (bootverbose)
		printf("%s:%d num_pages %d k_memsz %lu\n",__func__,__LINE__,num_pages,khdr->k_memsz);

	if (!va)
		va = kload_kmem_alloc(kernel_map, num_pages * PAGE_SIZE);

	if(!va || ((num_pages * PAGE_SIZE) > IMAGE_PREALLOC)) {
		printf("%s:%d  no mem 0x%lx or size over 24Meg %d\n",__func__,__LINE__,va,num_pages * PAGE_SIZE);
		return ENOMEM;
	}

	/*  need to set up a START dst page */
	for (i = 0; i < num_pages; i++) {
		kload_add_page(k_items, (vtophys(va + (i * PAGE_SIZE)) + KLOADBASE) | KLOAD_SOURCE);
	}
	printf("%s starting copyin... ",__func__);
	*k_items->item = KLOAD_DONE;
	if ((error = copyin(khdr->k_buf, (void *)va, khdr->k_memsz)) != 0)
		return error;
	printf("copied %d bytes to va %p done marker at %p\n",
	       (int)khdr->k_memsz, (void *)va, &k_items->item );

	return error;
}

int
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
		return error;

	/* hook into the shutdown/reboot path so we end up here before cpu reset */
	EVENTHANDLER_REGISTER(shutdown_final, kload_shutdown_final, NULL, SHUTDOWN_PRI_KLOAD);

	max_addr = 0;
	min_addr = ~0UL;

	if (bufsize != sizeof(struct kload)) {
		printf("Hmm size not right %jd %jd\n",(uintmax_t)bufsize,(uintmax_t)sizeof(struct kload));
		return error;
	}
	if ((error = copyin(uap->buf, &kld, bufsize)) != 0)
		return error;

	if (!k_items) {
		if((k_items = malloc(sizeof(struct kload_items),
				     M_KLOAD, M_WAITOK|M_ZERO)) == NULL)
			return ENOMEM;

		k_items->head = 0;
		k_items->head_va = 0;
		k_items->item = &k_items->head;
		k_items->last_item = &k_items->head;
	}

	control_page = kload_kmem_alloc(kernel_map, PAGE_SIZE * 2);
	k_cpage = (struct kload_cpage *)control_page;
	code_page = control_page + PAGE_SIZE;

	printf("copy from %p kernel_kump to 0x%lx size %d\n",
	       relocate_kernel, (unsigned long)code_page, relocate_kernel_size);
	memset((void *)control_page, 0, PAGE_SIZE * 2);
	memcpy((void *)code_page, relocate_kernel, relocate_kernel_size);

	k_cpage->kcp_magic = 0xC0DE;
	k_cpage->kcp_modulep = kld.k_modulep;
	k_cpage->kcp_physfree = kld.k_physfree;

	mygdt = (struct region_descriptor *)kload_kmem_alloc(
		kernel_map, PAGE_SIZE);
	k_cpage->kcp_gdt = (k_size_t)(vtophys(mygdt) + KLOADBASE);

	gdt_desc = (char *)mygdt + sizeof(struct region_descriptor);
	setup_freebsd_gdt(gdt_desc);
	mygdt->rd_limit = GUEST_GDTR_LIMIT;
	mygdt->rd_base = (unsigned long)(vtophys(gdt_desc) + KLOADBASE);

	/*
	 * we pass the virt addr of control_page but we need
	 * new virt addr as well
	 */
	k_cpage->kcp_cp = (k_size_t)(vtophys(control_page) + KLOADBASE);
	k_cpage->kcp_entry_pt = kld.k_entry_pt;

	/* 10 segments should be more than enough */
	for (i = 0 ; (i < kld.num_hdrs && i <= 10); i++)
		kload_copyin_segment(&kld.khdr[i], i);

	null_idt = (struct region_descriptor*)
		kload_kmem_alloc(kernel_map,PAGE_SIZE);
	k_cpage->kcp_idt = (k_size_t)vtophys(null_idt) + KLOADBASE;
	/* Wipe the IDT. */
	null_idt->rd_limit = 0;
	null_idt->rd_base = 0;
	/*
	 * This must be built after all other allocations so it can
	 * build a page table entry based on min max addresses
	 */
	/* returns new page table phys addr */
	kload_pgtbl = kload_build_page_table();
	if (!kload_pgtbl)
		return ENOMEM;
	k_cpage->kcp_pgtbl = (k_size_t)kload_pgtbl;

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
		kern_reboot(RB_KLOAD);
		/* should not return */
		mtx_unlock(&Giant);
	}
	/*
	 * the reboot code will do a module shutdown so it is not
	 * part kload_shutdown_final but it needs to happen.
	 * So in the case of exec run it here
	 */
	if (bootverbose)
		printf("%s: module_shutdown\n", __func__);
	kload_module_shutdown();
	kload_shutdown_final(NULL, RB_KLOAD);
just_load:
	printf("%s: Kernel image loaded waiting for reboot\n", __func__);
	return 0;
}

static void
kload_shutdown_final(void *arg, int howto)
{
	int ret;
	cpuset_t map;

	if (bootverbose)
		printf("%s arg %p howto 0x%x\n", __func__, arg, howto);

	if (!(howto & RB_KLOAD)) {
		printf("%s not a kload reboot\n", __func__);
		return;
	}
	/* Just to make sure we are on cpu 0 */
	KASSERT(PCPU_GET(cpuid) == 0, ("%s: not running on cpu 0", __func__));
	if (kload_ready) {

#if defined(SMP)
		if (bootverbose)
			printf("%s: suspend APs\n", __func__);
		map = all_cpus;
		CPU_CLR(PCPU_GET(cpuid), &map);
		CPU_NAND(&map, &stopped_cpus);
		if (!CPU_EMPTY(&map)) {
			printf("cpu_reset: Stopping other CPUs\n");
			suspend_cpus(map);
		}
#endif

		if (bootverbose)
			printf("%s: clear all handlers\n", __func__);
		intr_clear_all_handlers();

		if (bootverbose)
			printf("%s: loapic_clear_lapic\n", __func__);
		lapic_clear_lapic(1);

		intr_suspend();

		if (bootverbose)
			printf("%s disable_interrupts cpuid %d\n", 
			       __func__, PCPU_GET(cpuid));
		disable_intr();

		printf("calling relocate_kernel\n");
		ret = relocate_kernel(vtophys(k_items->head_va) + KLOADBASE,
				      /* dest addr i.e. overwrite existing kernel */
				      KERNBASE + (vm_paddr_t)kernphys,
				      vtophys(code_page) + KLOADBASE,
				      control_page);
	} else {
		printf("kload_shutdown_final called without a new kernel loaded\n");
	}
}

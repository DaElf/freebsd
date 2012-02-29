/*
 * Russell Cattelan Digital Elves Inc 2011
 */


#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/kload.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/bus.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/reboot.h>
#include <sys/eventhandler.h>
#include <sys/priv.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
#include <machine/intr_machdep.h>
#include <machine/apicvar.h>
#include <contrib/dev/acpica/include/acpi.h>

static struct kload_items *k_items = NULL;
MALLOC_DECLARE(M_KLOAD);
MALLOC_DEFINE(M_KLOAD, "kload_items", "kload items");
int kload_ready = 0;

typedef u_int64_t p4_entry_t;
typedef u_int64_t p3_entry_t;
typedef u_int64_t p2_entry_t;

static int kload_copyin_segment(struct kload_segment *,int);
static int kload_add_page(struct kload_items *items, unsigned long item_m);
static p4_entry_t *kload_build_page_table(void);
static void setup_freebsd_gdt(uint64_t *gdtr);
static void kload_shutdown_final(void *arg, int howto);

static struct gdt_desc_ptr *mygdt;
static	vm_offset_t control_page;
static	vm_offset_t code_page;
static 	void *gdt_desc;
static	p4_entry_t *pgtbl;
unsigned long kload_pgtbl;
static unsigned long max_addr = 0 , min_addr = 0;

extern void kload_module_shutdown(void);
extern unsigned long relocate_kernel(unsigned long indirection_page,
				     unsigned long page_list,
				     unsigned long code_page,
				     unsigned long control_page);
extern int relocate_kernel_size;
extern char kernphys[];

#define GIGMASK			(~((1<<30)-1))
#define KLOADBASE		KVADDR(KPML4I, (NPDPEPG-48), 0, 0)

#define	GUEST_NULL_SEL		0
#define	GUEST_CODE_SEL		1
#define	GUEST_DATA_SEL		2
#define	GUEST_GDTR_LIMIT	(3 * 8 - 1)

#define kload_kmem_alloc(map,size) kmem_alloc_attr(map, size,\
						   M_WAITOK | M_ZERO, \
						   0, (1 << 30) /* 1Gig limit */, \
						   VM_MEMATTR_WRITE_COMBINING)

struct kload_cpage {
	unsigned long kcp_magic;	/* 0 */
	unsigned long kcp_modulep;	/* 1 */
	unsigned long kcp_physfree;	/* 2 */
	unsigned long kcp_gdt;		/* 3 */
	unsigned long kcp_pgtbl;	/* 4 */
	unsigned long kcp_cp;		/* 5 */
	unsigned long kcp_entry_pt;	/* 6 */
	unsigned long kcp_idt;		/* 7 */
} __attribute__((packed)) ;

struct gdt_desc_ptr {
	unsigned short size;
	unsigned long address;
} __attribute__((packed)) ;

static void
setup_freebsd_gdt(uint64_t *gdtr)
{
	gdtr[GUEST_NULL_SEL] = 0x0000000000000000;
	gdtr[GUEST_CODE_SEL] = 0x0020980000000000;
	gdtr[GUEST_DATA_SEL] = 0x0000920000000000;
}

static void
update_max_min(vm_offset_t addr, int count) {

	int i;

	for(i = 0; i < count; i++) {
		if (vtophys(addr + (i * PAGE_SIZE)) < min_addr)
			min_addr = vtophys(addr + (i * PAGE_SIZE));
		if (vtophys(addr + (i * PAGE_SIZE)) > max_addr)
			max_addr = vtophys(addr + (i * PAGE_SIZE));
	}
}
static p4_entry_t *
kload_build_page_table(void) {

	unsigned long va;

	p4_entry_t *PT4;
	p4_entry_t *PT3;
	p4_entry_t *PT2;
	int i;

	va = (unsigned long)kmem_alloc(kernel_map,PAGE_SIZE * 3);

	PT4 = (p4_entry_t *)va;
	PT3 = (p4_entry_t *)(PT4 + (PAGE_SIZE / sizeof(unsigned long)));
	PT2 = (p4_entry_t *)(PT3 + (PAGE_SIZE / sizeof(unsigned long)));

	printf("%s PT4 0x%lx (0x%lx) PT3 0x%lx (0x%lx) PT2 0x%lx (0x%lx)\n",
	       __FUNCTION__,
	       (unsigned long)PT4, vtophys(PT4),
	       (unsigned long)PT3, vtophys(PT3),
	       (unsigned long)PT2, vtophys(PT2));


	bzero(PT4, PAGE_SIZE);
	bzero(PT3, PAGE_SIZE);
	bzero(PT2, PAGE_SIZE);

	if (max_addr > ((1 << 30)-1)) {
		/* make this a warn and fail in future
		 * but for now panic to debug
		 */
		panic("kload temp space spread over more than a 1gig range");
	}
	/*
	 * This is kinda brutal, but every single 1GB VM memory segment points to
	 * the same first 1GB of physical memory.  But it is more than adequate.
	 */
	for (i = 0; i < 512; i++) {
		/* Each slot of the level 4 pages points to the same level 3 page */
		PT4[i] = (p4_entry_t)(vtophys(PT3));
		PT4[i] |= PG_V | PG_RW | PG_U;

		/* Each slot of the level 3 pages points to the same level 2 page */
		PT3[i] = (p3_entry_t)(vtophys(PT2));
		PT3[i] |= PG_V | PG_RW | PG_U;

		/* The level 2 page slots are mapped with 2MB pages for 1GB. */
		PT2[i] = i * (2 * 1024 * 1024);
		PT2[i] |= PG_V | PG_RW | PG_PS | PG_U;
	}

	return (p4_entry_t *)vtophys(PT4);
}

static int
kload_add_page(struct kload_items *items, unsigned long item_m)
{
	if (*items->item != 0) {
		printf(" item != 0 0x%lx\n",*items->item);
		items->item++;
		items->i_count--;
	}

	if (bootverbose)
		printf("%s%d item 0x%lx\n", __FUNCTION__, __LINE__, (unsigned long)item_m);

	if ((items->item == items->last_item) || (items->i_count == 0)) {
		/* out of space in current page grab a new one */
		//struct  vm_page *m;
		vm_paddr_t phys = 0;
		unsigned long va;

		va = (unsigned long)kload_kmem_alloc(kernel_map,PAGE_SIZE);
		update_max_min(va,1);
		if (items->head_va == 0)
			items->head_va = va;

		phys = vtophys(va);
		if (bootverbose) {
			printf("%s indirect page item %p va %p stored %p phys %p\n",__FUNCTION__,
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

int
kload_copyin_segment(struct kload_segment *khdr, int seg) {

	int i;
	int num_pages;
	int error = 0;
	vm_offset_t va;

	num_pages = roundup2(khdr->k_memsz,PAGE_SIZE) >> PAGE_SHIFT;
	printf("%s:%d num_pages %d\n",__FUNCTION__,__LINE__,num_pages);

	va = kload_kmem_alloc(kernel_map, num_pages * PAGE_SIZE);
	update_max_min(va,num_pages);
	if(!va)
		return ENOMEM;


	/*  need to set up a START dst page */
	for (i = 0; i < num_pages; i++) {
		kload_add_page(k_items, (vtophys(va + (i * PAGE_SIZE)) + KLOADBASE) | KLOAD_SOURCE);
	}
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

	printf("%s: Says Hello!!!\n",__FUNCTION__);

	int error = 0;
	struct region_descriptor *null_idt;
	size_t bufsize = uap->buflen;
	struct kload kld;
	struct kload_cpage *k_cpage;
	int i;

	error = priv_check(td, PRIV_REBOOT);
	if (error)
		return error;

	EVENTHANDLER_REGISTER(shutdown_final, kload_shutdown_final, NULL, SHUTDOWN_PRI_KLOAD);
	printf("Reading from buf %p for len 0x%jx flags 0x%x\n",
	       uap->buf,(uintmax_t)bufsize,
	       uap->flags);

	max_addr = 0;
	min_addr = ~0UL;

	if (bufsize != sizeof(struct kload)) {
		printf("Hmm size not right %jd %jd\n",(uintmax_t)bufsize,sizeof(struct kload));
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
	update_max_min(control_page,2);
	code_page = control_page + PAGE_SIZE;

	printf("copy from %p kernel_kump to 0x%lx size %d\n",
	       relocate_kernel, (unsigned long)code_page, relocate_kernel_size);
	memset((void *)control_page, 0, PAGE_SIZE * 2);
	memcpy((void *)code_page, relocate_kernel, relocate_kernel_size);

	k_cpage->kcp_magic = 0xC0DE;
	k_cpage->kcp_modulep = kld.k_modulep;
	k_cpage->kcp_physfree = kld.k_physfree;

	mygdt = (struct gdt_desc_ptr *)kload_kmem_alloc(kernel_map,PAGE_SIZE);
	update_max_min((vm_offset_t)mygdt,1);
	k_cpage->kcp_gdt = (unsigned long)vtophys(mygdt) + KLOADBASE;

	gdt_desc = (char *)mygdt + sizeof(struct gdt_desc_ptr);
	setup_freebsd_gdt(gdt_desc);
	mygdt->size    = GUEST_GDTR_LIMIT;
	mygdt->address = (unsigned long)(vtophys(gdt_desc) + KLOADBASE);

	/* we pass the virt addr of control_page but we need
	 * new virt addr as well */
	k_cpage->kcp_cp = (unsigned long)(vtophys(control_page) + KLOADBASE);
	k_cpage->kcp_entry_pt = kld.k_entry_pt;

	/* 10 segments should be more than enough */
	for (i = 0 ; (i < kld.num_hdrs && i <= 10); i++) {
		kload_copyin_segment(&kld.khdr[i],i);
	}

	null_idt = (struct region_descriptor*)kload_kmem_alloc(kernel_map,PAGE_SIZE);
	k_cpage->kcp_idt = (unsigned long)vtophys(null_idt) + KLOADBASE;
	/* Wipe the IDT. */
	null_idt->rd_limit = 0;
	null_idt->rd_base = 0;
	/*
	 * This must be built after all other allocations so it can
	 * build a page table entry based on min max addresses
	 */
	/* returns new page table phys addr */
	pgtbl = kload_build_page_table();
	kload_pgtbl = (unsigned long)pgtbl;
	k_cpage->kcp_pgtbl = (unsigned long)pgtbl;

	kload_ready = 1;

	printf("%s:\n\t"
	       "thead_va         0x%lx (phys 0x%lx)\n\t"
	       "tkernbase        0x%lx\n\t"
	       "tcode_page       0x%lx (phys 0x%lx)\n\t"
	       "tcontrol_page    0x%lx (phys 0x%lx)\n\t"
	       "tgdt             0x%lx (phys 0x%lx)\n\t"
	       "tpgtbl                              (phys 0x%lx)\n\t"
	       "tidt             0x%lx (phys 0x%lx)\n\t"
	       "tk_entry_pt      0x%lx\n\t"
	       "tmax_addr                           (phys 0x%lx)\n\t"
	       "tmin_addr                           (phys 0x%lx)\n\t"
	       "tmodulep                            (phys 0x%lx)\n\t"
	       "physfree                            (phys 0x%lx)\n",
	       __FUNCTION__,
	       k_items->head_va, vtophys(k_items->head_va),
	       KERNBASE + (vm_paddr_t)kernphys,
	       control_page + PAGE_SIZE, vtophys(control_page + PAGE_SIZE),
	       control_page, vtophys(control_page),
	       (unsigned long)mygdt,vtophys(mygdt),(unsigned long)pgtbl,
	       (unsigned long)null_idt,vtophys(null_idt),
	       (unsigned long)kld.k_entry_pt,
	       (unsigned long)max_addr, (unsigned long)min_addr,
	       (unsigned long)kld.k_modulep, (unsigned long)kld.k_physfree);

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
	printf("%s: module_shutdown\n",__FUNCTION__);
	kload_module_shutdown();
	kload_shutdown_final(NULL, RB_KLOAD);
just_load:
	printf("%s: Kernel image loaded waiting for reboot\n",__FUNCTION__);
	return 0;
}


static void
kload_shutdown_final(void *arg, int howto)
{
	int ret;
	cpuset_t map;

	printf("%s arg %p howto 0x%x\n",__FUNCTION__, arg, howto);

#if 0
	if (!(howto & RB_KLOAD)) {
		printf("%s not a kload reboot\n",__FUNCTION__);
		return;
	}
#endif
	/* Just to make sure we are on cpu 0 */
	KASSERT(PCPU_GET(cpuid) == 0, ("%s: not running on cpu 0", __func__));
	if (kload_ready) {

		printf("%s: suspend APs\n",__FUNCTION__);
		map = all_cpus;
		// we should be bound to cpu 0 at this point
		printf("%s  cpuid %d\n",__FUNCTION__,PCPU_GET(cpuid));
		CPU_CLR(PCPU_GET(cpuid), &map);
		CPU_NAND(&map, &stopped_cpus);
		if (!CPU_EMPTY(&map)) {
			printf("cpu_reset: Stopping other CPUs\n");
			suspend_cpus(map);
		}

		//DELAY(5000000);

		printf("%s: clear all handlers\n",__FUNCTION__);
		intr_clear_all_handlers();

		printf("%s: loapic_clear_lapic\n",__FUNCTION__);
		lapic_clear_lapic(1);

		intr_suspend();

		printf("%s disable_interrupts cpuid %d\n",__FUNCTION__,PCPU_GET(cpuid));
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
		printf("kload_shutdown_final called without proper alt kernel load\n");
	}
}

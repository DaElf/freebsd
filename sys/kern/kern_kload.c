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

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>
//#include <machine/segments.h>
#include <machine/intr_machdep.h>
#include <contrib/dev/acpica/include/acpi.h>

static struct kload_items *k_items = NULL;
MALLOC_DECLARE(M_KLOAD);
MALLOC_DEFINE(M_KLOAD, "kload_items", "kload items");

int kload_active = 0;
int kload_step;

typedef u_int64_t p4_entry_t;
typedef u_int64_t p3_entry_t;
typedef u_int64_t p2_entry_t;

static int kload_copyin_segment(struct kload_segment *,int);
static int kload_add_page(struct kload_items *items, unsigned long item_m);
static p4_entry_t *kload_build_page_table(void);
static void setup_freebsd_gdt(uint64_t *gdtr);
int kload_exec(void);
int kload_exec_prep(void);
	
static struct gdt_desc_ptr *mygdt;
static	vm_offset_t control_page;
static 	void *gdt_desc;
static	p4_entry_t *pgtbl;
unsigned long kload_pgtbl;
static unsigned long max_addr = 0 , min_addr = 0;

extern void ipi_suspend_ap(void);
extern void kload_module_shutdown(void);
extern void shutdown_turnstiles(void);

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
	unsigned long kl_start;
	unsigned long pt_index;

	p4_entry_t *PT4;
	p4_entry_t *PT3;
	p4_entry_t *PT2;
	p4_entry_t *PT2KL;
	int i;
	
	va = (unsigned long)kload_kmem_alloc(kernel_map,PAGE_SIZE * 4);
	update_max_min(va,4);
	memset((void *)va, 0, 4 * PAGE_SIZE);

	PT4 = (p4_entry_t *)va;
	PT3 = (p4_entry_t *)(PT4 + (PAGE_SIZE / sizeof(unsigned long)));
	PT2 = (p4_entry_t *)(PT3 + (PAGE_SIZE / sizeof(unsigned long)));
	PT2KL = (p4_entry_t *)(PT2 + (PAGE_SIZE / sizeof(unsigned long)));

	printf("%s\tPT4 0x%lx (0x%lx)\n\tPT3 0x%lx (0x%lx)\n"
	       "\tPT2 0x%lx (0x%lx)\n\tPT2KL 0x%lx (0x%lx)\n",
	       __FUNCTION__,
	       (unsigned long)PT4, vtophys(PT4),
	       (unsigned long)PT3, vtophys(PT3),
	       (unsigned long)PT2, vtophys(PT2),
	       (unsigned long)PT2KL, vtophys(PT2KL));

	kl_start = min_addr & GIGMASK;
	pt_index = (KLOADBASE  >> PDPSHIFT) & ((1 << NPDPEPGSHIFT ) - 1);

	printf("\tmin_addr 0x%lx max_addr 0x%lx kl_start 0x%lx pt_index 0x%lx\n",
	       min_addr, max_addr, kl_start, pt_index);

	if (max_addr > (min_addr +(1 << 30))) {
		/* make this a warn and fail in future
		 * but for now panic to debug
		 */
		panic("kload temp space spread over more than a 1gig range");
	}
		
	for (i = 0; i < 512; i++) {
		/* The level 2 page slots are mapped with 2MB pages for 1GB. */
		PT2[i] = i * (2 * 1024 * 1024);
		PT2[i] |= PG_V | PG_RW | PG_PS | PG_U;

		PT2KL[i] = (i * (2 * 1024 * 1024)) + kl_start;
		PT2KL[i] |= PG_V | PG_RW | PG_PS | PG_U;
	}
	PT4[KPML4I]  = (p4_entry_t)(vtophys(PT3));
	PT4[KPML4I] |= PG_V | PG_RW | PG_U;
	// map offset 0 since btext set the warm boot flag @ 0x472
	// maybe btext should write KERNBASE + 0x472 
	// or better yet set warm boot at shutdown time not startup
	PT4[0]       = (p4_entry_t)(vtophys(PT3));
	PT4[0]      |= PG_V | PG_RW | PG_U;

	PT3[KPDPI]  = (p3_entry_t)(vtophys(PT2));
	PT3[KPDPI] |= PG_V | PG_RW | PG_U;
	// ditto 
	PT3[0]      = (p3_entry_t)(vtophys(PT2));
	PT3[0]     |= PG_V | PG_RW | PG_U;

	PT3[pt_index]  = (p3_entry_t)(vtophys(PT2KL));
	PT3[pt_index] |= PG_V | PG_RW | PG_U;

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

#if 0
	printf("%s%d item 0x%lx\n",
	       __FUNCTION__, __LINE__,
	       (unsigned long)item_m);
#endif

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
		printf("%s indirect page item %p va %p stored %p phys %p\n",__FUNCTION__,
		       (void *)*items->item,
		       (void *)va,
		       (void *)(vtophys(va) + KLOADBASE),
		       (void *)phys );
		/* store the address of indrect page */
		//*items->item = (unsigned long)phys | KLOAD_INDIRECT;
		*items->item = (unsigned long)(vtophys(va) + KLOADBASE) | KLOAD_INDIRECT;
		items->item = (unsigned long *)va;
		/* ok now move to new page to start storing address */
		items->last_item = (unsigned long *)va + ((PAGE_SIZE/sizeof(unsigned long)) - 1);
		items->i_count = ((PAGE_SIZE/sizeof(unsigned long)) - 1);
	}
	*items->item = item_m;
#if 0
	printf("%s:%d item %p item_m %p\n",__FUNCTION__,__LINE__, items->item, (void *)item_m);
#endif
	items->item++;
	items->i_count--;
	//*items->item = 0;

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
		//printf("pages phys 0x%lx\n",(unsigned long)vtophys(va + (i * PAGE_SIZE)));
		kload_add_page(k_items, (vtophys(va + (i * PAGE_SIZE)) + KLOADBASE)
			       | KLOAD_SOURCE); 
	}
	*k_items->item = KLOAD_DONE;
	if ((error = copyin(khdr->k_buf, (void *)va, khdr->k_memsz)) != 0)
                return error;
	printf("copied %d bytes to va %p done marker at %p\n",
	       (int)khdr->k_memsz, (void *)va,
	       &k_items->item );

	return error;
}

extern unsigned long
relocate_kernel(unsigned long indirection_page,
		unsigned long page_list,
		unsigned long code_page,
		unsigned long control_page);
extern int relocate_kernel_size;

int
sys_kload(struct thread *td, struct kload_args *uap)
{
	printf("%s:%d Says Hello!!!\n",__FUNCTION__,__LINE__);
	
	int error = 0;
	struct region_descriptor *null_idt;
	vm_offset_t code_page;
        size_t bufsize = uap->buflen;
	struct kload kld;
	int i;
	int ret;

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
	update_max_min(control_page,2);
	code_page = control_page + PAGE_SIZE;

	printf("copy from %p kernel_kump to 0x%lx size %d\n",
	       relocate_kernel, (unsigned long)code_page, relocate_kernel_size);
	memset((void *)control_page, 0, PAGE_SIZE * 2);
	memcpy((void *)code_page, relocate_kernel, relocate_kernel_size);

	((unsigned long *)control_page)[0] = 0xC0DE;
	((unsigned long *)control_page)[1] = kld.k_modulep;
	((unsigned long *)control_page)[2] = kld.k_physfree;

	mygdt = (struct gdt_desc_ptr *)kload_kmem_alloc(kernel_map,PAGE_SIZE);
	update_max_min((vm_offset_t)mygdt,1);
	((unsigned long *)control_page)[3] = (unsigned long)vtophys(mygdt) + KLOADBASE;
	
	gdt_desc = (char *)mygdt + sizeof(struct gdt_desc_ptr);
	printf ("gdt %p paddr(0x%lx) size gdt_desc %lu gdt_desc %p\n",
		mygdt, vtophys(mygdt),
		sizeof(struct gdt_desc_ptr), gdt_desc);
	
	setup_freebsd_gdt(gdt_desc);
	mygdt->size    = GUEST_GDTR_LIMIT;
	mygdt->address = (unsigned long)(vtophys(gdt_desc) + KLOADBASE);


	/* we pass the virt addr of control_page but we need
	 * new virt addr as well */
	((unsigned long *)control_page)[5] =
		(unsigned long)(vtophys(control_page) + KLOADBASE);

	((unsigned long *)control_page)[6] = (unsigned long)kld.k_entry_pt;
	if(uap->flags & 0x4) {
	  //	kload_reboot();
		intr_clear_all_handlers();
	}

	printf("\tnum_hdrs %d\n",kld.num_hdrs);
	/* 10 segments should be more than enough */
	for (i = 0 ; (i < kld.num_hdrs && i <= 10); i++) {
		printf("\tsegment %d entry_pt 0x%lx\n",i,kld.k_entry_pt);
		kload_copyin_segment(&kld.khdr[i],i);
	}

	null_idt = (struct region_descriptor*)kload_kmem_alloc(kernel_map,PAGE_SIZE);
	((unsigned long *)control_page)[7] = (unsigned long)vtophys(null_idt) + KLOADBASE;
	/* Wipe the IDT. */
	null_idt->rd_limit = 0;
	null_idt->rd_base = 0;
	//lidt(&null_idt);

	/* this must be built after all other allocations so it can
	 * caculate build a page table entry based on min max alloc space
	 */
	/* returns new page table phys addr */
	pgtbl = kload_build_page_table();
	kload_pgtbl = (unsigned long)pgtbl;
	((unsigned long *)control_page)[4] = (unsigned long)pgtbl;

	printf("%s:\n\thead_va\t\t0x%lx (phys 0x%lx)\n"
	       "\tkernbase\t0x%lx\n"
	       "\tcode_page\t0x%lx (phys 0x%lx)\n"
	       "\tcontrol_page\t0x%lx (phys 0x%lx)\n"
	       "\tgdt\t\t0x%lx (0x%lx)\n"
	       "\tpgtbl\t\t\t\t0x%lx\n"
	       "\tidt\t\t0x%lx (0x%lx)\n"
	       "\tmax_addr\t\t\t(0x%lx)\n"
	       "\tmin_addr\t\t\t(0x%lx)\n",
	       __FUNCTION__,
	       k_items->head_va, vtophys(k_items->head_va),
	       KERNBASE + 0x200000,
	       control_page + PAGE_SIZE, vtophys(control_page + PAGE_SIZE),
	       control_page, vtophys(control_page),
	       (unsigned long)mygdt,vtophys(mygdt),(unsigned long)pgtbl,
	       (unsigned long)null_idt,vtophys(null_idt),
	       (unsigned long)max_addr, (unsigned long)min_addr );

	// really do it vs just testing
	if(!(uap->flags & 0x8))
		goto just_testing;
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

	// now that we are cpu 0 send ipi to stop other cpu's
	//ipi_suspend_ap();
#endif
	printf("%s: suspend APs\n",__FUNCTION__);
	{
		cpuset_t map;
		
		map = all_cpus;
		//CPU_CLR(0, &map);
		// we should be bound to cpu 0 at this point
		printf("%s  cpuid %d\n",__FUNCTION__,PCPU_GET(cpuid));
		CPU_CLR(PCPU_GET(cpuid), &map);
		CPU_NAND(&map, &stopped_cpus);
		if (!CPU_EMPTY(&map)) {
			printf("cpu_reset: Stopping other CPUs\n");
			//stop_cpus_hard(map);
			suspend_cpus(map);
		}
	}

	//DELAY(5000000);		/* wait ~5000mS */
	printf("%s: module_shutdown\n",__FUNCTION__);
	kload_module_shutdown();

	printf("%s: clear all handlers\n",__FUNCTION__);
	intr_clear_all_handlers();

#if 1	
	printf("%s: shutdown_turstiles\n",__FUNCTION__);
	shutdown_turnstiles();
#endif
#if 0
	/* not really sure what this will do but lets try it and see */
	printf("%s: AcpiTerminate\n",__FUNCTION__);
	AcpiTerminate();
	//	printf("%s AcpiDisable\n",__FUNCTION__);
	//AcpiDisable();
#endif
	
	printf("%s disable_interrupts cpuid %d\n",__FUNCTION__,PCPU_GET(cpuid));
	disable_intr();
	intr_suspend();

	/* only pass the control page under the current page table
	 * the rest of the address should be based on new page table
	 * which is a simple phys + KLOADBASE mapping */
	printf("calling relocate_kernel\n");
	ret = relocate_kernel(vtophys(k_items->head_va) + KLOADBASE,
			      /* dest addr i.e. overwrite existing kernel */
			      KERNBASE + 0x200000,
			      vtophys(code_page) + KLOADBASE,
			      control_page);
	printf("\trelocate_new_kernel returned %d\n",ret);
just_testing:
	printf("%s just testing not really trying to reboot\n",__FUNCTION__);
		
	return 0;
}

/* need to split things apart so we can wander into the reboot shutdown code and
 * then back
 */
int kload_exec_prep(void) {
	return 0;
}

int
kload_exec(void)
{
	return 0;
}

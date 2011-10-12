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

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>

static struct kload_items *k_items = NULL;
MALLOC_DECLARE(M_KLOAD);
MALLOC_DEFINE(M_KLOAD, "kload_items", "kload items");

int kload_active = 0;
int kload_step;
u_int64_t kload_modulep;
u_int64_t kload_physfree;

typedef u_int64_t p4_entry_t;
typedef u_int64_t p3_entry_t;
typedef u_int64_t p2_entry_t;

static int kload_copyin_segment(struct kload_segment *,int);
int kload_copyin_segment_old(struct kload_segment *,int);
static int kload_add_page(struct kload_items *items, unsigned long item_m);
static p4_entry_t *kload_build_page_table(void);
static void setup_freebsd_gdt(uint64_t *gdtr);
int kload_reboot(void);
int kload_reboot_prep(void);
	
static struct gdt_desc_ptr *gdt;
static	vm_offset_t control_page;
static 	void *gdt_desc;
static	p4_entry_t *pgtbl;


extern struct timecounter *timecounter;
extern struct timecounter dummy_timecounter;
extern void kload_module_shutdown(void);
extern struct mtx icu_lock;
extern struct mtx dt_lock;
#ifdef WITNESS
extern struct mtx w_mtx;
#endif
extern int witness_cold;
extern struct mtx clock_lock;

extern void shutdown_turnstiles(void);

//extern p4_entry_t PT4[];
//extern p3_entry_t PT3[];
//extern p2_entry_t PT2[];

#define	GUEST_NULL_SEL		0
#define	GUEST_CODE_SEL		1
#define	GUEST_DATA_SEL		2
#define	GUEST_GDTR_LIMIT	(3 * 8 - 1)

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


#define VTOP(x) x
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
//	printf("%s:%d add page 0x%lx\n",__FUNCTION__,__LINE__,item_m);
	if (*items->item != 0) {
		printf(" item != 0 0x%lx\n",*items->item);
		items->item++;
		items->i_count--;
	}

#if 0
	printf("%s%d item %p last_item %p head 0x%lx i_count %d\n",__FUNCTION__,
	       __LINE__,
	       items->item,
	       items->last_item,
	       items->head,
	       items->i_count );
#endif
	if ((items->item == items->last_item) || (items->i_count == 0)) {
		/* out of space in current page grab a new one */
		//struct  vm_page *m;
		vm_paddr_t phys = 0;
		unsigned long va;

		//va = (unsigned long)malloc(PAGE_SIZE, M_TEMP, M_WAITOK|M_ZERO);
		va = (unsigned long)kmem_alloc(kernel_map,PAGE_SIZE);
		if (items->head_va == 0)
			items->head_va = va;
		
		phys = vtophys(va);
		printf("%s indirect page item %p va %p stored %p phys %p\n",__FUNCTION__,
		       (void *)*items->item,
		       (void *)va,
		       (void *)(vtophys(va) + KERNBASE),
		       (void *)phys );
		/* store the address of indrect page */
		//*items->item = (unsigned long)phys | KLOAD_INDIRECT;
		*items->item = (unsigned long)(vtophys(va) + KERNBASE) | KLOAD_INDIRECT;
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
//	int pperp; 
//	int extra_pages;
//	unsigned long *pages_va = NULL;
//	vm_object_t obj;
//	vm_paddr_t phys;

	/* create vm_object for each segemet */
//	obj = vm_object_allocate(OBJT_DEFAULT, seg);
	
//	VM_OBJECT_LOCK(obj);
	num_pages = roundup2(khdr->k_memsz,PAGE_SIZE) >> PAGE_SHIFT;
	printf("%s:%d num_pages %d\n",__FUNCTION__,__LINE__,num_pages);

#if 0
	pperp = PAGE_SIZE / sizeof(unsigned long);
	/* assume pperp will always be a power of 2 */
	extra_pages = roundup2(num_pages, pperp) / pperp;
	printf("extra_pages %d\n", extra_pages);
	extra_pages = roundup2(num_pages + extra_pages, pperp) / pperp;
	printf("extra_pages %d\n", extra_pages);

	pages_va = (unsigned long *)kmem_alloc(kernel_map, extra_pages);
	khdr->k_pages = pages_va;
	/* ----- */	
#endif

	//va = kload_kmem_alloc(kernel_map, num_pages * PAGE_SIZE, pages_va);
	va = kmem_alloc(kernel_map, num_pages * PAGE_SIZE);
	if(!va)
		return ENOMEM;


	/*  need to set up a START dst page */
	for (i = 0; i < num_pages; i++) {
	  //printf("pages phys 0x%lx\n",(unsigned long)vtophys(va + (i * PAGE_SIZE)));
	  kload_add_page(k_items, (vtophys(va + (i * PAGE_SIZE)) + KERNBASE)
			 | KLOAD_SOURCE);
	  //kload_add_page(k_items, (va + (i * PAGE_SIZE))| KLOAD_SOURCE);
	}
	*k_items->item = KLOAD_DONE;
	if ((error = copyin(khdr->k_buf, (void *)va, khdr->k_memsz)) != 0)
                return error;
	printf("copied %d bytes to va %p done marker at %p\n",
	       (int)khdr->k_memsz, (void *)va,
	       &k_items->item );


	return error;
}

#if 0
int foo_foo_foo(void) {
	printf("%s:%d Says Hello!!!\n",__FUNCTION__,__LINE__);
	printf("Hi simple %d\n",6);
}
#endif

#if 1
unsigned long
relocate_kernel(unsigned long indirection_page,
		unsigned long page_list,
		unsigned long code_page,
		unsigned long control_page);
extern int relocate_kernel_size;
#else
unsigned long
relocate_kernel(void);
#endif

int
kload(struct thread *td, struct kload_args *uap)
{
	
	printf("%s:%d Says Hello!!!\n",__FUNCTION__,__LINE__);
	
	int error = 0;
	//struct gdt_desc_ptr *gdt;
	//vm_offset_t control_page;
	vm_offset_t code_page;
	//void *gdt_desc;
	//p4_entry_t *pgtbl;
        size_t bufsize = uap->buflen;
	struct kload kld;
	int i;
	int ret;

	printf("Reading from buf %p for len 0x%jx flags 0x%x\n",
	       uap->buf,(uintmax_t)bufsize,
	       uap->flags);

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


	control_page = kmem_alloc(kernel_map, PAGE_SIZE * 2);
	code_page = control_page + PAGE_SIZE;

	printf("copy from %p kernel_kump to 0x%lx size %d\n",
	       relocate_kernel, (unsigned long)code_page, relocate_kernel_size);
	memset((void *)control_page, 0, PAGE_SIZE * 2);
	memcpy((void *)code_page, relocate_kernel, relocate_kernel_size);

	((unsigned long *)control_page)[0] = 0xC0DE;
	((unsigned long *)control_page)[1] = kload_modulep;
	((unsigned long *)control_page)[2] = kload_physfree;
	       
	

	gdt = (struct gdt_desc_ptr *)kmem_alloc(kernel_map,PAGE_SIZE);
	((unsigned long *)control_page)[3] = (unsigned long)vtophys(gdt) + KERNBASE;
	
	gdt_desc = (char *)gdt + sizeof(struct gdt_desc_ptr);
	printf ("gdt %p paddr(0x%lx) size gdt_desc %lu gdt_desc %p\n",
		gdt, vtophys(gdt),
		sizeof(struct gdt_desc_ptr), gdt_desc);
	
	setup_freebsd_gdt(gdt_desc);
	gdt->size    = GUEST_GDTR_LIMIT;
	gdt->address = (unsigned long)(vtophys(gdt_desc) + KERNBASE);

	/* returns new page table phys addr */
	pgtbl = kload_build_page_table();
	((unsigned long *)control_page)[4] = (unsigned long)pgtbl;

	/* we pass the virt addr of control_page but we need
	 * new virt addr as well */
	((unsigned long *)control_page)[5] =
		(unsigned long)(vtophys(control_page) + KERNBASE);

	if(uap->flags & 0x4) {
		kload_reboot();
	}

	printf("\tnum_hdrs %d\n",kld.num_hdrs);
	/* 10 segments should be more than enough */
	for (i = 0 ; (i < kld.num_hdrs && i <= 10); i++) {
		printf("\tsegment %d entry_pt 0x%lx\n",i,kld.khdr[i].k_entry_pt);
		kload_copyin_segment(&kld.khdr[i],i);
	}

	printf("%s:\thead_va\t0x%lx (phys 0x%lx)\n"
	       "\tkernbase\t0x%lx\n"
	       "\tcode_page\t0x%lx (phys 0x%lx)\n"
	       "\tcontrol_page\t0x%lx (phys 0x%lx)\n"
	       "\tgdt\t0x%lx (0x%lx)\n"
	       "\tpgtbl\t0x%lx\n",
	       __FUNCTION__,
	       k_items->head_va, vtophys(k_items->head_va),
	       KERNBASE + 0x200000,
	       control_page + PAGE_SIZE, vtophys(control_page + PAGE_SIZE),
	       control_page, vtophys(control_page),
	       (unsigned long)gdt,vtophys(gdt),(unsigned long)pgtbl );
	/* only pass the control page under the current page table
	 * the rest of the address should be based on new page table
	 * which is a simple phys + KERNBASE mapping */
	ret = relocate_kernel(vtophys(k_items->head_va) + KERNBASE,
			      KERNBASE + 0x200000,
			      vtophys(code_page) + KERNBASE,
			      control_page);
	printf("\trelocate_new_kernel returned %d\n",ret);
		
	return 0;
}


int kernel_jump(unsigned long gdt,unsigned long pgtbl);
int kernel_jump_simple(unsigned long modulep, unsigned long physfree,
		       unsigned long gdt, unsigned long pgtbl);
int kload_reboot_prep(void) {

	vm_offset_t code_page;

	control_page = kmem_alloc(kernel_map, PAGE_SIZE * 2);
	code_page = control_page + PAGE_SIZE;
	printf("%s control_page 0x%lx (phys 0x%lx) code_page 0x%lx (phys) 0x%lx)\n",
	       __FUNCTION__, control_page, vtophys(control_page),
	       control_page + PAGE_SIZE, vtophys(control_page + PAGE_SIZE));

	printf("copy from %p kernel_kump to 0x%lx size %d\n",
	       kernel_jump, (unsigned long)code_page, relocate_kernel_size);
	memset((void *)control_page, 0, PAGE_SIZE * 2);
	memcpy((void *)code_page, kernel_jump, relocate_kernel_size);

	gdt = (struct gdt_desc_ptr *)kmem_alloc(kernel_map,PAGE_SIZE);
	gdt_desc = (char *)gdt + sizeof(struct gdt_desc_ptr);
	printf ("gdt %p paddr(0x%lx) size gdt_desc %lx gdt_desc %p\n",
		gdt, vtophys(gdt),
		sizeof(struct gdt_desc_ptr), gdt_desc);
	
	setup_freebsd_gdt(gdt_desc);
	gdt->size    = GUEST_GDTR_LIMIT;
	gdt->address = (unsigned long)gdt_desc;

	pgtbl = kload_build_page_table();
	return 0;
}

int
kload_reboot(void)
{
	int ret = 0;

	printf("%s calling kernel_jump with modulep 0x%lx physfree 0x%lx "
	       "gdt 0x%lx pgtbl 0x%lx\n",
	       __FUNCTION__,
	       kload_modulep, kload_physfree,
	       (unsigned long)gdt,(unsigned long)pgtbl);
	
	/* quick and dirty hack to shutdown all modules
	 * including the bloody clock
	 */
	kload_active = 1;
	kload_step = 1;
	printf("\tkload_active %p (%d) kload_step %p (%d)\n",&kload_active, kload_active,
	       &kload_step, kload_step);

#if 1
//	kload_module_shutdown();
	
	mtx_destroy(&icu_lock);
	mtx_destroy(&dt_lock);
	// It looks like somebody still has a ref on Giant at shutdown
	mtx_unlock(&Giant);
	mtx_destroy(&clock_lock);
	mutex_shutdown();
	shutdown_turnstiles();
	
	witness_cold = 1;
	timecounter = &dummy_timecounter;
#endif
#if 0
	ret = kernel_jump_simple(
		kload_modulep,
		kload_physfree,
		(unsigned long)gdt,
		(unsigned long)pgtbl);
#endif
	printf("kernel_jump returned %d\n",ret);
	return 0;
}

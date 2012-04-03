/*
 * Russell Cattelan Digital Elves Inc 2012
 */


#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/malloc.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_map.h>



#define	GUEST_NULL_SEL		0
#define	GUEST_CODE_SEL		1
#define	GUEST_DATA_SEL		2

pt_entry_t * kload_build_page_table(void);
void setup_freebsd_gdt(uint64_t *gdtr);

void
setup_freebsd_gdt(uint64_t *gdtr)
{
	gdtr[GUEST_NULL_SEL] = 0x0000000000000000;
	gdtr[GUEST_CODE_SEL] = 0x0020980000000000;
	gdtr[GUEST_DATA_SEL] = 0x0000920000000000;
}

pt_entry_t *
kload_build_page_table(void) {
	unsigned long va;
	pt_entry_t *PT4;
	pt_entry_t *PT3;
	pt_entry_t *PT2;
	int i;

	va = (unsigned long)kmem_alloc(kernel_map,PAGE_SIZE * 3);
	PT4 = (pt_entry_t *)va;
	PT3 = (pt_entry_t *)(PT4 + (PAGE_SIZE / sizeof(unsigned long)));
	PT2 = (pt_entry_t *)(PT3 + (PAGE_SIZE / sizeof(unsigned long)));
	
	if (bootverbose)
		printf("%s PT4 0x%lx (0x%lx) PT3 0x%lx (0x%lx) PT2 0x%lx (0x%lx)\n",
		       __FUNCTION__,
		       (unsigned long)PT4, (unsigned long)vtophys(PT4),
		       (unsigned long)PT3, (unsigned long)vtophys(PT3),
		       (unsigned long)PT2, (unsigned long)vtophys(PT2));

	bzero(PT4, PAGE_SIZE);
	bzero(PT3, PAGE_SIZE);
	bzero(PT2, PAGE_SIZE);

	/*
	 * This is kinda brutal, but every single 1GB VM memory segment points to
	 * the same first 1GB of physical memory.  But it is more than adequate.
	 */
	for (i = 0; i < 512; i++) {
		/* Each slot of the level 4 pages points to the same level 3 page */
		PT4[i] = (pt_entry_t)(vtophys(PT3));
		PT4[i] |= PG_V | PG_RW | PG_U;

		/* Each slot of the level 3 pages points to the same level 2 page */
		PT3[i] = (pt_entry_t)(vtophys(PT2));
		PT3[i] |= PG_V | PG_RW | PG_U;

		/* The level 2 page slots are mapped with 2MB pages for 1GB. */
		PT2[i] = i * (2 * 1024 * 1024);
		PT2[i] |= PG_V | PG_RW | PG_PS | PG_U;
	}
	return (pt_entry_t *)vtophys(PT4);
}

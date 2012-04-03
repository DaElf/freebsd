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

#define	GUEST_RCODE_SEL		3
#define	GUEST_RDATA_SEL		4

#define	GUEST_UCODE_SEL		5
#define	GUEST_UDATA_SEL		6

#define	GUEST_TSS_SEL		6
#define	GUEST_GDTR_LIMIT	(8 * 8 - 1)

/*
		.word 0x0,0x0,0x0,0x0		# Null entry
		.word 0xffff,0x0,0x9a00,0xcf	# SEL_SCODE
		.word 0xffff,0x0,0x9200,0xcf	# SEL_SDATA
		.word 0xffff,0x0,0x9a00,0x0	# SEL_RCODE
		.word 0xffff,0x0,0x9200,0x0	# SEL_RDATA
		.word 0xffff,MEM_USR,0xfa00,0xcf# SEL_UCODE
		.word 0xffff,MEM_USR,0xf200,0xcf# SEL_UDATA
		.word _TSSLM,MEM_TSS,0x8900,0x0 # SEL_TSS
*/
static void
setup_freebsd_gdt(uint64_t *gdtr)
{
	gdtr[GUEST_NULL_SEL]  = 0x0000000000000000ull;

	gdtr[GUEST_CODE_SEL]  = 0x00cf9b000000FFFFull;
	gdtr[GUEST_DATA_SEL]  = 0x00cf93000000FFFFull;

	gdtr[GUEST_RCODE_SEL] = 0x00009b000000FFFFull;
	gdtr[GUEST_RDATA_SEL] = 0x000092000000FFFFull;

	gdtr[GUEST_UCODE_SEL] = 0x00cffb00a000FFFFull;
	gdtr[GUEST_UDATA_SEL] = 0x00cff300a000FFFFull;
	//0x5f982067      0x00008b00
	gdtr[GUEST_TSS_SEL]   = 0x6720985f008b0000ull;
}

static pt_entry_t *
kload_build_page_table(void) {

	unsigned long va;
	pt_entry_t *pde;
	pt_entry_t *pte;
	int i;

	va = (unsigned long)kmem_alloc(kernel_map,PAGE_SIZE * 2);
	memset((void *)va, 0, PAGE_SIZE * 2);
	pde = (pt_entry_t *)va;
	pte = (pt_entry_t *)(pde + (PAGE_SIZE / sizeof(pt_entry_t)));

	printf("%s pde 0x%lx (0x%lx) pte 0x%lx (0x%lx)\n",
	       __FUNCTION__,
	       (unsigned long)pde, (unsigned long)vtophys(pde),
	       (unsigned long)pte, (unsigned long)vtophys(pte));

	for (i = 0; i < 1024; i++) {
		/* Each slot of the level 3 pages points to the same level 2 page */
		//pde[i] = (pt_entry_t)(vtophys(pte));
		// identity map the first 1G 4 times.
		pde[i] = (i % 256) * (4 * 1024 * 1024);
		pde[i] |= PG_V | PG_RW | PG_U | PG_PS;

		/* The level 2 page slots are mapped with 2MB pages for 1GB. */
		//pte[i] = i * (2 * 1024 * 1024);
		//pte[i] |= PG_V | PG_RW | PG_PS | PG_U;
	}

	return (pt_entry_t *)vtophys(pde);
}


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
//#include <vm/vm_extern.h>
//#include <vm/vm_map.h>

struct kload_items *g_items = NULL;
MALLOC_DECLARE(M_KLOAD);
MALLOC_DEFINE(M_KLOAD, "kload_items", "kload items");

static int kload_copyin_segment(struct kload_segment *,int);

static struct vm_page*
kload_grab_page(struct kload_items *items, int seg) {

	struct vm_object *obj;
	struct vm_page *m = NULL;

	if (!items->kload_obj) 
		obj = items->kload_obj = vm_object_allocate(OBJT_DEFAULT, seg);

	VM_OBJECT_LOCK(obj);
	m = vm_page_grab(obj, 0, VM_ALLOC_NOBUSY | VM_ALLOC_WIRED | VM_ALLOC_ZERO | VM_ALLOC_RETRY);
	VM_OBJECT_UNLOCK(obj);

	return m;
}


static int kload_add_page(struct kload_items *items, unsigned long item_m, int seg)
{
//	printk("%s:%d\n",__FUNCTION__,__LINE__);
	if (*items->item != 0)
		items->item++;

	if (items->item == items->last_item) {
		/* out of space in current page grab a new one */
		struct  vm_page *m;
		vm_paddr_t phys;

		m = kload_grab_page(items, seg);
		if (!m)
			return ENOMEM;

		phys = VM_PAGE_TO_PHYS(m);
		phys |= KLOAD_INDIRECT;
		printf("%s:%d item %p vm_page %p phys %p\n",__FUNCTION__,__LINE__,
		       (void *)*items->item,
		       m,
		       (void *)phys );
		*items->item = (unsigned long)phys;
		image->entry = ;
		items->last_item = (unsigned long)phys + ((PAGE_SIZE/sizeof(unsigned long)) - 1);
	}
	*items->item = item_m;
	items->item++;
	*items->item = 0;
	printf("%s:%d item 0x%p\n",__FUNCTION__,__LINE__,(void *)item_m);

	return 0;
}

static int 
kload_copyin_segment(struct kload_segment *khdr, int seg) {

	int i;
	int num_pages;
	int error = 0;
	vm_object_t obj;
	vm_paddr_t phys;

	/* create vm_object for each segemet */
	obj = vm_object_allocate(OBJT_DEFAULT, seg);
	
	VM_OBJECT_LOCK(obj);
	num_pages = roundup2(khdr->k_memsz,PAGE_SIZE) >> PAGE_SHIFT;
	printf("%s:%d num_pages %d\n",__FUNCTION__,__LINE__,num_pages);
	for (i = 0 ; i < num_pages; i++) {
		struct vm_page *m;
		printf("%s:%d segment %d\n",__FUNCTION__,__LINE__,i);

		m = vm_page_grab(obj, i, VM_ALLOC_NOBUSY | VM_ALLOC_WIRED | VM_ALLOC_ZERO | VM_ALLOC_RETRY);
			
		phys = VM_PAGE_TO_PHYS(m);
		kload_add_page(g_items, (unsigned long)phys, seg);
		
		//printf("%s phys page %p phys 0x%jx\n",__FUNCTION__,m,(uintmax_t)phys);
		/* store vmpage to a list */
	}
	VM_OBJECT_UNLOCK(obj);

	return error;
}

unsigned long
relocate_kernel(unsigned long indirection_page,
		unsigned long page_list,
		unsigned long start_address);
int
kload(struct thread *td, struct kload_args *uap)
{
	
	printf("%s:%d Says Hello!!!\n",__FUNCTION__,__LINE__);
	
	int error = 0;
        size_t bufsize = uap->buflen;
	struct kload kld;
	int i;
	int ret;

	printf("Reading from buf 0x%p for len 0x%jx flags 0x%x\n",
	       uap->buf,(uintmax_t)bufsize,
	       uap->flags);

	if (bufsize != sizeof(struct kload)) {
		printf("Hmm size not right %jd\n",(uintmax_t)bufsize);
		return error;
	}
        if ((error = copyin(uap->buf, &kld, bufsize)) != 0)
                return error;

	if (!g_items)
		if((g_items = malloc(sizeof(struct kload_items),M_KLOAD, M_WAITOK)) == NULL)
		    return ENOMEM;

	printf("num_hdrs %d\n",kld.num_hdrs);
	/* 10 segments should be more than enough */
	for (i = 0 ; (i < kld.num_hdrs && i <= 10); i++) {
		kload_copyin_segment(&kld.khdr[i],i);
	}
	
	ret = relocate_kernel(1,2,3);
	printf("relocate_new_kernel returned %d\n",ret);
		
	return 0;
}

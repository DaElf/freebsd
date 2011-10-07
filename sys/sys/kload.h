/* Russell Cattelan Digital Elves Inc 2011 */


#define KLOAD_LOAD		 0
#define KLOAD_REBOOT		(1 << 0 )
#define KLOAD_EXEC		(1 << 0 )
#define KLOAD_TEST_RELOCATE	(1 << 10)

struct kload_segment {
	void		       *k_buf;
	size_t			k_memsz;
	unsigned long	       *k_pages;
	unsigned long		k_entry_pt;
};
	
struct kload {
	/* This may only be partially filled in.
	 * OR could create our own segment describtor structure */
//	struct Elf_Phdr phdr[10];
	struct kload_segment khdr[10];
	int num_hdrs;
};

//typedef unsigned long kload_item_t;
#define KLOAD_DESTINATION  0x1
#define KLOAD_INDIRECT     0x2
#define KLOAD_DONE         0x4
#define KLOAD_SOURCE       0x8

struct kload_items {
	unsigned long head;
	vm_offset_t head_va;
	unsigned long *last_item;
	unsigned long *item;
	int i_count;
  
	
	unsigned long flags;  /* not used yet */
  //struct vm_object *kload_obj;
};




/* Russell Cattelan Digital Elves Inc 2011 */

/* This heavily borrowed from userboot/test/test.c */

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/kload.h>

#include <userboot.h>

#define ENTER() printf("%s:%d Enter\n",__FUNCTION__,__LINE__);
#define EXIT() printf("%s:%d Exit\n",__FUNCTION__,__LINE__);

char *host_base = "/";
/* how can we get rid of these? I don't think we need them */

struct termios term, oldterm;
char *image;
size_t image_size;
size_t image_max_used = 0;
int disk_fd = -1;
uint64_t regs[16];
uint64_t pc;
static int execute = 0;
static void *dl_lib;

typedef void *(*M_func)(size_t bytes, const char *file, int line);

M_func Malloc_func;

static void k_exit(void *, int);
int kload_load_image(void *image,unsigned long entry_pt);

struct load_file {
	int l_isdir;
	size_t l_size;
	struct stat l_stat;
	union {
		int fd;
		DIR *dir;
	} l_u;
};


struct smap {
        uint64_t       base;
        uint64_t       length;
        uint32_t       type;
} __packed;


static int
name2oid(char *name, int *oidp)
{
	int oid[2];
	int i;
	size_t j;

	oid[0] = 0;
	oid[1] = 3;

	j = CTL_MAXNAME * sizeof(int);
	i = sysctl(oid, 2, oidp, &j, name, strlen(name));
	if (i < 0)
		return (i);
	j /= sizeof(int);

	printf("%s: oid %d %d\n",__FUNCTION__,oidp[0],oidp[1]);
	return j;
}

static void
k_putc(void *arg, int chr) {
	write(1, &chr,1);
}

static int
k_getc(void *arg) {
	char chr;
	if(read(0,&chr,1) == 1)
		return chr;
	return -1;
}

static int
k_poll(void *arg) {
	int n;
	if (ioctl(0, FIONREAD, &n) >= 0)
		return (n > 0);
	return 0;
}

static int
k_open(void *arg, const char *filename, void **lf_ret) {
	struct stat st;
	struct load_file *lf;
	int error = -1;
	char path[PATH_MAX];
		
	//printf("%s:%d filename %s\n",__FUNCTION__,__LINE__,filename);
	if (!host_base) {
		printf("Host base not set\n");
		return ENOENT;
	}

	strlcpy(path, host_base, PATH_MAX);
	if (path[strlen(path) - 1] == '/')
		path[strlen(path) - 1] = 0;
	strlcat(path, filename, PATH_MAX);
	lf = malloc(sizeof(struct load_file));
	if (stat(path, &lf->l_stat) < 0) {
		error = errno;
		goto out;
	}

	lf->l_size = st.st_size;
	if (S_ISDIR(lf->l_stat.st_mode)) {
		lf->l_isdir = 1;
		lf->l_u.dir = opendir(path);
		if (!lf->l_u.dir) {
			error = EINVAL;
			goto out;
		}
                *lf_ret = lf;
		return 0;
	}
	if (S_ISREG(lf->l_stat.st_mode)) {
		lf->l_isdir = 0;
		lf->l_u.fd = open(path, O_RDONLY);
		if (lf->l_u.fd < 0) {
			error = EINVAL;
			goto out;
		}
                *lf_ret = lf;
		return 0;
	}

out:
	free(lf);
	//printf("%s error %d\n",__FUNCTION__,error);
	return error;
}

static int
k_close(void *arg, void *h)
{
	struct load_file *lf = (struct load_file *)h;
	
	//printf("%s:%d\n",__FUNCTION__,__LINE__);

	if (lf->l_isdir)
		closedir(lf->l_u.dir);
	else
		close(lf->l_u.fd);
	free(lf);

	return 0;
}


static int
k_isdir(void *arg, void *h) {
	ENTER();
	return (((struct load_file *)h)->l_isdir);
}

static int
k_read(void *arg, void *h, void *dst, size_t size, size_t *resid_return) {
	struct load_file *lf = (struct load_file *)h;
	ssize_t sz;

//	printf("%s:%d fd %d dest addr %p size %d\n",__FUNCTION__,__LINE__,lf->l_u.fd,dst,size);
	if (lf->l_isdir)
		return EINVAL;

	if((sz = read(lf->l_u.fd, dst, size)) < 0)
		return EINVAL;
	*resid_return = size - sz;
	return 0;
}

static int
k_readdir(void *arg, void *h, uint32_t *fileno_return, uint8_t *type_return,
    size_t *namelen_return, char *name) {
	struct load_file *lf = (struct load_file *)h;
	struct dirent *dp;

	printf("%s:%d\n",__FUNCTION__,__LINE__);
	if (!lf->l_isdir)
		return EINVAL;

	dp = readdir(lf->l_u.dir);
	if (!dp)
		return ENOENT;

	/*
	 * Note: d_namlen is in the range 0..255 and therefore less
	 * than PATH_MAX so we don't need to test before copying.
	 */
	*fileno_return = dp->d_fileno;
	*type_return = dp->d_type;
	*namelen_return = dp->d_namlen;
	memcpy(name, dp->d_name, dp->d_namlen);
	name[dp->d_namlen] = 0;

	return 0;
}

static int
k_seek(void *arg, void *h, uint64_t offset, int whence) {
	struct load_file *lf = (struct load_file *)h;
	//printf("%s offset %lld\n",__FUNCTION__, offset);

	if (lf->l_isdir)
		return EINVAL;

	if (lseek(lf->l_u.fd, offset, whence) < 0)
		return errno;

	return 0;
}

static int
k_stat(void *arg, void *h,
       int *mode_return, int *uid_return,
       int *gid_return, uint64_t *size_return) {

	struct load_file *lf = (struct load_file *)h;

	//printf("%s:%d\n",__FUNCTION__,__LINE__);
	*mode_return = lf->l_stat.st_mode;
	*uid_return = lf->l_stat.st_uid;
	*gid_return = lf->l_stat.st_gid;
	*size_return = lf->l_stat.st_size;
	return 0;
}

static int
k_diskread(void *arg, int unit, uint64_t offset, void *dst, size_t size,
    size_t *resid_return) {
	ssize_t n;
	ENTER();

	if (unit != 0 || disk_fd == -1)
		return EIO;
	n = pread(disk_fd, dst, size, offset);
	if (n < 0)
		return errno;
	*resid_return = size - n;
	return 0;
}

/*
 * This is really confusing since this is not really like doing copyin / copyout in kernel land
 * this will copy the data pointed to by the "from" ptr  and copy "to" the offset into the load image
 * this should be called copy_to_image
 */
static int
k_copyin(void *arg, const void *from, uint64_t to, size_t size) {

  //  	printf("%s:%d from %p to 0x%jx size %d\n",__FUNCTION__,__LINE__,from,to,size);
	to &= 0x7fffffff;
	if (to > image_size)
		return (EFAULT);
	if (to + size > image_size) {
		size = image_size - to;
		printf("WARNING this should never happen\n");
	}
	memcpy(&image[to], from, size);

	if (to + size > image_max_used) 
		image_max_used = to + size;

	return 0;
}

/*
 * copyout is copying FROM the image at "from" offset to memory pointed to by to ptr 
 * this should be copy_from_image
 */
static int
k_copyout(void *arg, uint64_t from, void *to, size_t size) {

	//printf("%s:%d from %p to 0x%jx size %d caller 0x%x\t",__FUNCTION__,__LINE__,from,to,size,__builtin_return_address(0));
	from &= 0x7fffffff;
	if (from > image_size)
		return (EFAULT);
	if (from + size > image_size)
		size = image_size - from;
	memcpy(to, &image[from], size);
	
	return 0;
}

static void
k_setreg(void *arg, int r, uint64_t v) {
	//printf("%s:%d r 0x%x v 0x%jx\n",__FUNCTION__,__LINE__,r,v);
	if (r < 0 || r >= 16)
		return;
	regs[r] = v;
}

static void
k_setmsr(void *arg, int r, uint64_t v) {
	//printf("%s:%d r 0x%x v 0x%jx\n",__FUNCTION__,__LINE__,r,v);
}

static void
k_setcr(void *arg, int r, uint64_t v) {
	//printf("%s:%d r 0x%x v 0x%jx\n",__FUNCTION__,__LINE__,r,v);
}

static void
k_setgdt(void *arg, uint64_t v, size_t sz) {
	//printf("%s:%d v 0x%jx size 0x%x\n",__FUNCTION__,__LINE__,v,sz);
}

static void
k_exec(void *arg, uint64_t entry_pt) {
	printf("Execute at 0x%jx\n", entry_pt);
	printf("image size max used %jd endof page %jd\n",image_max_used,roundup2(image_max_used,PAGE_SIZE));
	kload_load_image(image,entry_pt);
	k_exit(arg, 0);
}

static void
k_delay(void *arg, int usec) {
	usleep(usec);
}

static void
k_exit(void *arg, int v) {
	tcsetattr(0, TCSAFLUSH, &oldterm);
	exit(v);
}

static void
k_getmem(void *arg, uint64_t *lowmem, uint64_t *highmem) {

	int mib[2];
	unsigned long long physmem;
	size_t len;
	
	mib[0] = CTL_HW;
	mib[1] = HW_PHYSMEM;
	len = sizeof(physmem);
	sysctl(mib, 2, &physmem, &len, NULL, 0);

        *lowmem = physmem;
        *highmem = 0;

	printf("%s:%d lowmem %ju highmem %ju\n",__FUNCTION__,__LINE__,
	       *lowmem,
	       *highmem
		);
}

static int
k_buildsmap(void *arg, void **smap_void, size_t *outlen) {

	size_t i,j;
	size_t len;
	char name[] = "hw.smap";
	int mib[CTL_MAXNAME];
	struct smap *smapbase;

	len = name2oid(name, mib);

	/* get the size	 */
	i = sysctl(mib, 2, 0, &j, 0, 0);
	printf("Size %jd\n",j);
	len = j;

	/* this is a nasty hack to allocate memory here
	 * and free it in useboot.so bios_addsmapdata
	 * need to use Malloc from libstand since
	 * userboot functions will use Free from libstand
	 */
	smapbase = Malloc_func(j,__FILE__,__LINE__);
	if (!smapbase) {
		printf("kload failed to allocate space for smap\n");
		return 1;
	}
	
	i = sysctl(mib, 2, smapbase, &j, NULL, 0);

	*outlen = len;
	*smap_void = smapbase;

	{
		struct smap *smap, *smapend;
		smapend = (struct smap *)((uintptr_t)smapbase + len);
		for (smap = smapbase; smap < smapend; smap++) {
			printf("\ttype %d base 0x%016lx length 0x%016lx\n",
			       smap->type,smap->base, smap->length);
		}
	}

	return 0;
}




struct loader_callbacks_v1 cb = {

	.open = k_open,
	.close = k_close,
	.isdir = k_isdir,
	.read = k_read,
	.readdir = k_readdir,
	.seek = k_seek,
	.stat = k_stat,

	.diskread = k_diskread,

	.copyin = k_copyin,
	.copyout = k_copyout,
	.setreg = k_setreg,
	.setmsr = k_setmsr,
	.setcr = k_setcr,
        .setgdt = k_setgdt,
	.exec = k_exec,

	.delay = k_delay,
	.exit = k_exit,
        .getmem = k_getmem,
	
	.putc = k_putc,
	.getc = k_getc,
	.poll = k_poll,
	.buildsmap = k_buildsmap,
};

static void
usage(void) {
	printf("usage: kload [-d <disk image path>] [-h <host filesystem path>] -e\n");
	exit(1);
}

int
main(int argc, char** argv) {
	void (*func)(struct loader_callbacks_v1 *, void *, int, int);
	int opt;
	char *disk_image = NULL;

	while ((opt = getopt(argc, argv, "d:h:e")) != -1) {
		switch (opt) {
		case 'd':
			disk_image = optarg;
			break;

		case 'h':
			host_base = optarg;
			break;
		case 'e':
			execute = 1;
			break;

		case '?':
			usage();
		}
	}

//	dl_lib = dlopen("/boot/userboot.so", RTLD_LOCAL);
	dl_lib = dlopen("userboot.so", RTLD_LOCAL);
	if (!dl_lib) {
		printf("%s\n", dlerror());
		return (1);
	}
	func = dlsym(dl_lib, "loader_main");
	if (!func) {
		printf("%s\n", dlerror());
		return (1);
	}
	/* this is a hack for now */
	Malloc_func = dlsym(dl_lib, "Malloc");
	if (!Malloc_func) {
		printf("%s\n", dlerror());
		return (1);
	}


	image_size = 128*1024*1024;
	image = malloc(image_size);
	if (disk_image) {
		disk_fd = open(disk_image, O_RDONLY);
		if (disk_fd < 0)
			err(1, "Can't open disk image '%s'", disk_image);
	}

	tcgetattr(0, &term);
	oldterm = term;
	term.c_iflag &= ~(ICRNL);
	term.c_lflag &= ~(ICANON|ECHO);
	tcsetattr(0, TCSAFLUSH, &term);

	func(&cb, NULL, USERBOOT_VERSION_1, disk_fd >= 0);

}

int
kload_load_image(void *image,unsigned long entry_pt) {
  
	struct kload kld;
	int syscall_num = 532;
	int flags = KLOAD_LOAD;
	char *stack = (char *)image + 0x1000;
	
	kld.khdr[0].k_buf = &((char *)image)[0x200000];
	kld.khdr[0].k_memsz = roundup2(image_max_used,PAGE_SIZE) - 0x200000;
	kld.k_entry_pt = entry_pt;
	kld.num_hdrs=1;


	printf("modulep 0x%x kernend 0x%x\n",
	       ((unsigned int *)stack)[1],
	       ((unsigned int *)stack)[2]);
	
	/* hack for now ... pull from the stack page 
	 * fix the interface to pass as parameters
	 */
	kld.k_modulep  =  ((unsigned int *)stack)[1];
	kld.k_physfree =  ((unsigned int *)stack)[2];

	printf("loading k_buf %p with size %jd to kernel image addr %p entry_pt 0x%jx\n",
	       kld.khdr[0].k_buf,
	       kld.khdr[0].k_memsz,
	       image,
	       kld.k_entry_pt);
	if (execute)
		flags |= 0x8;

	return syscall (syscall_num,&kld,sizeof(struct kload),flags);
	return 1;
}

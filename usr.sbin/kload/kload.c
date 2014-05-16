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

/*
 * process kill code borrowed from halt.c
 */

#include <sys/param.h>
#include <sys/kload.h>
#include <sys/ioctl.h>
#include <sys/module.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/param.h>

#include <machine/pc/bios.h>

#include <dirent.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <userboot.h>
#include <unistd.h>

char *host_base = "/";
/* how can we get rid of these? I don't think we need them */

struct termios term, oldterm;
char *image;
size_t image_size;
size_t image_max_used = 0;
int disk_fd = -1;
uint64_t regs[16];
uint64_t pc;
static int k_execute = 0;
static int k_reboot = 0;
static void *dl_lib;
typedef void *(*M_func)(size_t bytes, const char *file, int line);
M_func Malloc_func;
static void k_exit(void *, int);
static int shutdown_processes(void);
static u_int get_pageins(void);
static int kload_load_image(void *image,unsigned long entry_pt);

struct load_file {
	int l_isdir;
	size_t l_size;
	struct stat l_stat;
	union {
		int fd;
		DIR *dir;
	} l_u;
};

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

	return (j);
}

static void
k_putc(void *arg, int chr)
{
	write(1, &chr, 1);
}

static int
k_getc(void *arg)
{
	char chr;
	if(read(0, &chr, 1) == 1)
		return (chr);
	return (-1);
}

static int
k_poll(void *arg)
{
	int n;
	if (ioctl(0, FIONREAD, &n) >= 0)
		return (n > 0);
	return 0;
}

static int
k_open(void *arg, const char *filename, void **lf_ret)
{
	struct stat st;
	struct load_file *lf;
	int error = -1;
	char path[PATH_MAX];

	if (!host_base) {
		printf("Host base not set\n");
		return (ENOENT);
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
		return (0);
	}
	if (S_ISREG(lf->l_stat.st_mode)) {
		lf->l_isdir = 0;
		lf->l_u.fd = open(path, O_RDONLY);
		if (lf->l_u.fd < 0) {
			error = EINVAL;
			goto out;
		}
		*lf_ret = lf;
		return (0);
	}

out:
	free(lf);
	return (error);
}

static int
k_close(void *arg, void *h)
{
	struct load_file *lf = (struct load_file *)h;

	if (lf->l_isdir)
		closedir(lf->l_u.dir);
	else
		close(lf->l_u.fd);
	free(lf);

	return (0);
}

static int
k_isdir(void *arg, void *h)
{
	return (((struct load_file *)h)->l_isdir);
}

static int
k_read(void *arg, void *h, void *dst, size_t size, size_t *resid_return)
{
	struct load_file *lf = (struct load_file *)h;
	ssize_t sz;

	if (lf->l_isdir)
		return (EINVAL);

	if((sz = read(lf->l_u.fd, dst, size)) < 0)
		return (EINVAL);
	*resid_return = size - sz;
	return (0);
}

static int
k_readdir(void *arg, void *h, uint32_t *fileno_return, uint8_t *type_return,
    size_t *namelen_return, char *name)
{
	struct load_file *lf = (struct load_file *)h;
	struct dirent *dp;

	if (!lf->l_isdir)
		return (EINVAL);

	dp = readdir(lf->l_u.dir);
	if (!dp)
		return (ENOENT);

	/*
	 * Note: d_namlen is in the range 0..255 and therefore less
	 * than PATH_MAX so we don't need to test before copying.
	 */
	*fileno_return = dp->d_fileno;
	*type_return = dp->d_type;
	*namelen_return = dp->d_namlen;
	memcpy(name, dp->d_name, dp->d_namlen);
	name[dp->d_namlen] = 0;

	return (0);
}

static int
k_seek(void *arg, void *h, uint64_t offset, int whence)
{
	struct load_file *lf = (struct load_file *)h;

	if (lf->l_isdir)
		return (EINVAL);

	if (lseek(lf->l_u.fd, offset, whence) < 0)
		return (errno);

	return (0);
}

static int
k_stat(void *arg, void *h,
       int *mode_return, int *uid_return,
       int *gid_return, uint64_t *size_return)
{

	struct load_file *lf = (struct load_file *)h;

	*mode_return = lf->l_stat.st_mode;
	*uid_return = lf->l_stat.st_uid;
	*gid_return = lf->l_stat.st_gid;
	*size_return = lf->l_stat.st_size;
	return (0);
}

static int
k_diskread(void *arg, int unit, uint64_t offset, void *dst, size_t size,
    size_t *resid_return)
{
	ssize_t n;

	if (unit != 0 || disk_fd == -1)
		return (EIO);
	n = pread(disk_fd, dst, size, offset);
	if (n < 0)
		return (errno);
	*resid_return = size - n;
	return (0);
}

static int
k_diskioctl(void *arg, int unit, u_long cmd, void *data)
{
	/* not supported on by kload */
	return (ENOTTY);
}

/*
 * This is really confusing since this is not really like doing copyin / copyout
 * in kernel land this will copy the data pointed to by the "from" ptr and copy
 * "to" the offset into the load image
 */
static int
k_copy_to_image(void *arg, const void *from, uint64_t to, size_t size)
{
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

	return (0);
}

/*
 * copyout is copying FROM the image at "from" offset to memory pointed to by to
 * ptr
 */
static int
k_copy_from_image(void *arg, uint64_t from, void *to, size_t size)
{
	from &= 0x7fffffff;
	if (from > image_size)
		return (EFAULT);
	if (from + size > image_size)
		size = image_size - from;
	memcpy(to, &image[from], size);

	return (0);
}

static void
k_setreg(void *arg, int r, uint64_t v)
{
	if (r < 0 || r >= 16)
		return;
	regs[r] = v;
}

static void
k_setmsr(void *arg, int r, uint64_t v)
{
	/* Unneeded */
}

static void
k_setcr(void *arg, int r, uint64_t v)
{
	/* Unneeded */
}

static void
k_setgdt(void *arg, uint64_t v, size_t sz)
{
	/* Unneeded */
}

static void
k_exec(void *arg, uint64_t entry_pt)
{
#ifdef DEBUG
	printf("Execute at 0x%jx\n", entry_pt);
	printf("image size max used %jd endof page %jd\n", image_max_used,
	    roundup2(image_max_used, PAGE_SIZE));
#endif
	kload_load_image(image, entry_pt);
	k_exit(arg, 0);
}

static void
k_delay(void *arg, int usec)
{
	usleep(usec);
}

static void
k_exit(void *arg, int v)
{
	tcsetattr(0, TCSAFLUSH, &oldterm);
	exit(v);
}

static void
k_getmem(void *arg, uint64_t *lowmem, uint64_t *highmem)
{
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

static const char *
k_getenv(void *arg, int idx)
{
	static const char *vars[] = {
		NULL
	};

	return (vars[idx]);
}

static int
k_buildsmap(void *arg, void **smap_void, size_t *outlen)
{
	struct bios_smap_xattr *smapbasex, *smapx, *smapendx;
	struct bios_smap *smapbase, *smap;
	size_t i,j;
	size_t len;
	char name[] = "machdep.smap";
	int mib[CTL_MAXNAME];

	len = name2oid(name, mib);

	/* get the current smap from the running system */
	i = sysctl(mib, 2, 0, &j, 0, 0);
	len = j;

	/*
	 * Use the malloc function from libstand/userboot.so since
	 * bios_addsmapdata will free the memory using the libstand Free
	 * so be careful to use not use standard malloc here
	 */
	smapbasex = malloc(j);
	smapbase = Malloc_func(j, __FILE__, __LINE__);
	if (!smapbase || !smapbasex) {
		printf("kload failed to allocate space for smap\n");
		return (1);
	}

	i = sysctl(mib, 2, smapbasex, &j, NULL, 0);

	smapendx = (struct bios_smap_xattr *)((uintptr_t)smapbasex + len);
	for (smapx = smapbasex, smap = smapbase; smapx < smapendx; smapx++, smap++ ) {
		smap->type = smapx->type;
		smap->base = smapx->base;
		smap->length = smapx->length;
		printf("\ttype %d base 0x%016lx length 0x%016lx\n",
		       smap->type, smap->base, smap->length);
	}

	*outlen = ((uintptr_t)smap - (uintptr_t)smapbase);
	*smap_void = smapbase;
	printf("exit smapbase 0x%016lx smap 0x%016lx length %zu orig len %zu\n",
	       (uintptr_t)smapbase, (uintptr_t)smap,  *outlen, len);
	free(smapbasex);
	return 0;
}

struct loader_callbacks cb = {

	.open = k_open,
	.close = k_close,
	.isdir = k_isdir,
	.read = k_read,
	.readdir = k_readdir,
	.seek = k_seek,
	.stat = k_stat,

	.diskread = k_diskread,
	.diskioctl = k_diskioctl,

	.copyin = k_copy_to_image,
	.copyout = k_copy_from_image,
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
	.getenv = k_getenv,
	.buildsmap = k_buildsmap,
};

static void
usage(void)
{
	printf("usage: kload [-d <disk image path>] "
	    "[-h <host filesystem path>] [-e | -r]\n");
	exit(1);
}

int
main(int argc, char** argv)
{
	int (*loader_main)(struct loader_callbacks *, void *, int, int);
	void (*loader_init)(void);
	int (*setenv)(const char *, const char *, int);
	int opt;
	char *disk_image = NULL;
	char karg[20];
	char kval[128];
	char *loader = NULL;

	if (geteuid()) {
		errno = EPERM;
		err(1, NULL);
	}

	while ((opt = getopt(argc, argv, "d:h:l:erk:")) != -1) {
		switch (opt) {
		case 'd':
			disk_image = optarg;
			break;

		case 'h':
			host_base = optarg;
			break;
		case 'l':
			if (loader != NULL)
				err(1, "-l can only be given once");
			loader = strdup(optarg);
			if (loader == NULL)
				err(1, "malloc");
			break;
		case 'e':
			k_execute = 1;
			break;
		case 'r':
			k_reboot = 1;
			break;
		case 'k':
			memset(karg,0,sizeof(karg));
			memset(kval,0,sizeof(kval));
			if(sscanf(optarg,"%[a-zA-Z_-]=%s",karg,kval) == 2) {
				printf("got value %s %s\n",karg,kval);
				setenv(karg, kval, 1);
			} else {
				fprintf(stderr,"-k failure %s\n",optarg);
			}
			break;
		case '?':
			usage();
		}
	}

	if (loader != NULL) {
		dl_lib = dlopen(loader, RTLD_LOCAL);
		free(loader);
	} else {
		dl_lib = dlopen("/boot/userboot.so", RTLD_LOCAL);
	}
	if (!dl_lib) {
		printf("%s\n", dlerror());
		return (1);
	}
	loader_main = dlsym(dl_lib, "loader_main");
	if (!loader_main) {
		printf("%s\n", dlerror());
		return (1);
	}
	Malloc_func = dlsym(dl_lib, "Malloc");
	if (!Malloc_func) {
		printf("%s\n", dlerror());
		return (1);
	}
	/*
	 * pull in the libstand setenv for setting name value pairs
	 * in the kernel env page
	 */
	setenv = dlsym(dl_lib, "setenv");
	if (!setenv) {
		printf("%s\n", dlerror());
		return (1);
	}
	loader_init = dlsym(dl_lib, "loader_init");
	if (!loader_init) {
		printf("%s\n", dlerror());
		return (1);
	}
	/* call libstand setheap to init memory allocations */
	loader_init();


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

	return(loader_main(&cb, NULL, USERBOOT_VERSION_4, disk_fd >= 0));
}

static int
kload_load_image(void *image, unsigned long entry_pt)
{
	char *stack = (char *)image + 0x1000; /* PAGESIZE */
	struct kload kld;
	int flags = KLOAD_LOAD;
	int modid, syscall_num;
	int ret;
	struct module_stat stat;

	/*
	 * This must the same value sys/conf/ldscript.xxx
	 * This value was changed at one point when a new version
	 * of binutils was imported. The value is aligned to
	 * max page size supported by given processor
	 */
	unsigned long kernphys = 0x200000;

	kld.khdr[0].k_buf = &((char *)image)[kernphys];
	kld.khdr[0].k_memsz = roundup2(image_max_used,PAGE_SIZE) - kernphys;
	kld.k_entry_pt = entry_pt;
	kld.num_hdrs = 1;

	/*
	 * pull paramaters from the stack page
	 * a better interface should be developed for kload
	 * in the future
	 */
	kld.k_modulep = ((unsigned int *)stack)[1];
	kld.k_physfree = ((unsigned int *)stack)[2];

	/*
	 * Make sure there is 4 pages of kenv pages between the end of the
	 * kernel and start of free memory.
	 * Why you ask? Well that is a question without a good answer as of yet
	 * for some strange reason some ata chips will not respond correctly
	 * unless free memory starts at greater than 2 pages out.
	 * The obvoius assumption is that something is getting stommped on but
	 * that has yet to be determined. Adding this workaround.
	 */
	kld.k_physfree = MAX(kld.k_modulep + (4 * PAGE_SIZE), kld.k_physfree);

	printf("WARNING kernphys set to 0x%lx make sure this matches kernphys "
	    "from sys/config/ldscript\n", kernphys);

	if (k_execute) {
		flags &= ~KLOAD_REBOOT;
		flags |= KLOAD_EXEC;
	}
	if (k_reboot) {
		flags &= ~KLOAD_EXEC;
		flags |= KLOAD_REBOOT;
		shutdown_processes();
	}

	stat.version = sizeof(stat);
	if ((modid = modfind("sys/kload")) == -1)
		err(1, "modfind");
	if (modstat(modid, &stat) != 0)
		err(1, "modstat");
	syscall_num = stat.data.intval;

	ret = syscall(syscall_num, &kld, sizeof(struct kload), flags);

	printf("kload syscall %d ret %d\n", syscall_num, ret);

	return ret;
}

static int
shutdown_processes(void)
{
	int i;
	u_int pageins;
	int sverrno;
	/*
	 * Do a sync early on, so disks start transfers while we're off
	 * killing processes.  Don't worry about writes done before the
	 * processes die, the reboot system call syncs the disks.
	 */
	sync();

	/*
	 * Ignore signals that we can get as a result of killing
	 * parents, group leaders, etc.
	 */
	(void)signal(SIGHUP,  SIG_IGN);
	(void)signal(SIGINT,  SIG_IGN);
	(void)signal(SIGQUIT, SIG_IGN);
	(void)signal(SIGTERM, SIG_IGN);
	(void)signal(SIGTSTP, SIG_IGN);

	/*
	 * If we're running in a pipeline, we don't want to die
	 * after killing whatever we're writing to.
	 */
	(void)signal(SIGPIPE, SIG_IGN);

	/* Just stop init -- if we fail, we'll restart it. */
	if (kill(1, SIGTSTP) == -1)
		err(1, "SIGTSTP init");

	/* Send a SIGTERM first, a chance to save the buffers. */
	if (kill(-1, SIGTERM) == -1 && errno != ESRCH)
		err(1, "SIGTERM processes");

	/*
	 * After the processes receive the signal, start the rest of the
	 * buffers on their way.  Wait 5 seconds between the SIGTERM and
	 * the SIGKILL to give everybody a chance. If there is a lot of
	 * paging activity then wait longer, up to a maximum of approx
	 * 60 seconds.
	 */
	sleep(2);
	for (i = 0; i < 20; i++) {
		pageins = get_pageins();
		sync();
		sleep(3);
		if (get_pageins() == pageins)
			break;
	}

	for (i = 1;; ++i) {
		if (kill(-1, SIGKILL) == -1) {
			if (errno == ESRCH)
				break;
			goto restart;
		}
		if (i > 5) {
			(void)fprintf(stderr,
			    "WARNING: some process(es) wouldn't die\n");
			break;
		}
		(void)sleep(2 * i);
	}
	return 1;
restart:
	sverrno = errno;
	errx(1, "%s%s", kill(1, SIGHUP) == -1 ?
	    "(can't restart init): " : "", strerror(sverrno));
	/* NOTREACHED */
	return 0;
}

static u_int
get_pageins(void)
{
	u_int pageins;
	size_t len;

	len = sizeof(pageins);
	if (sysctlbyname("vm.stats.vm.v_swappgsin", &pageins, &len, NULL, 0)
	    != 0) {
		warnx("v_swappgsin");
		return (0);
	}
	return (pageins);
}

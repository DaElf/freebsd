/*
 * Copyright (C) 1993-2000 by Darren Reed.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and due credit is given
 * to the original author and the contributors.
 *
 * @(#)ip_compat.h	1.8 1/14/96
 * $Id: ip_compat.h,v 2.26.2.3 2000/04/28 14:56:49 darrenr Exp $
 */

#ifndef	__IP_COMPAT_H__
#define	__IP_COMPAT_H__

#ifndef	__P
# ifdef	__STDC__
#  define	__P(x)  x
# else
#  define	__P(x)  ()
# endif
#endif
#ifndef	__STDC__
# undef		const
# define	const
#endif

#ifndef	SOLARIS
#define	SOLARIS	(defined(sun) && (defined(__svr4__) || defined(__SVR4)))
#endif
#if SOLARIS2 >= 8
# ifndef	USE_INET6
#  define	USE_INET6
# endif
#endif

#if defined(_KERNEL) || defined(KERNEL) || defined(__KERNEL__)
# undef	KERNEL
# undef	_KERNEL
# undef 	__KERNEL__
# define	KERNEL
# define	_KERNEL
# define 	__KERNEL__
#endif

#if defined(__SVR4) || defined(__svr4__) || defined(__sgi)
#define index   strchr
# if !defined(KERNEL)
#  define	bzero(a,b)	memset(a,0,b)
#  define	bcmp		memcmp
#  define	bcopy(a,b,c)	memmove(b,a,c)
# endif
#endif

#ifndef offsetof
#define offsetof(t,m) (int)((&((t *)0L)->m))
#endif

#if defined(__sgi) || defined(bsdi)
struct  ether_addr {
        u_char  ether_addr_octet[6];
};
#endif

#if defined(__sgi) && !defined(IPFILTER_LKM)
# ifdef __STDC__
#  define IPL_EXTERN(ep) ipfilter##ep
# else
#  define IPL_EXTERN(ep) ipfilter/**/ep
# endif
#else
# ifdef __STDC__
#  define IPL_EXTERN(ep) ipl##ep
# else
#  define IPL_EXTERN(ep) ipl/**/ep
# endif
#endif

#ifdef	linux
# include <sys/sysmacros.h>
#endif
#if	SOLARIS
# define	MTYPE(m)	((m)->b_datap->db_type)
# include	<sys/isa_defs.h>
# include	<sys/ioccom.h>
# include	<sys/sysmacros.h>
# include	<sys/kmem.h>
/*
 * because Solaris 2 defines these in two places :-/
 */
# undef	IPOPT_EOL
# undef	IPOPT_NOP
# undef	IPOPT_LSRR
# undef	IPOPT_RR
# undef	IPOPT_SSRR
# ifndef	KERNEL
#  define	_KERNEL
#  undef	RES_INIT
#  if SOLARIS2 >= 8
#   include <netinet/ip6.h>
#  endif
#  include <inet/common.h>
#  include <inet/ip.h>
#  include <inet/ip_ire.h>
#  undef	_KERNEL
# else /* _KERNEL */
#  if SOLARIS2 >= 8
#   include <netinet/ip6.h>
#  endif
#  include <inet/common.h>
#  include <inet/ip.h>
#  include <inet/ip_ire.h>
# endif /* _KERNEL */
# if SOLARIS2 >= 8
#  include <inet/ip_if.h>
#  include <netinet/ip6.h>
#  define	ipif_local_addr	ipif_lcl_addr
/* Only defined in private include file */
#  ifndef	V4_PART_OF_V6
#   define	V4_PART_OF_V6(v6)	v6.s6_addr32[3]
#  endif
# endif
#else
# if !defined(__sgi)
typedef	 int	minor_t;
#endif
#endif /* SOLARIS */
#define	IPMINLEN(i, h)	((i)->ip_len >= ((i)->ip_hl * 4 + sizeof(struct h)))

#ifndef	IP_OFFMASK
#define	IP_OFFMASK	0x1fff
#endif

#if	BSD > 199306
# define	USE_QUAD_T
# define	U_QUAD_T	u_quad_t
# define	QUAD_T		quad_t
#else /* BSD > 199306 */
# define	U_QUAD_T	u_long
# define	QUAD_T		long
#endif /* BSD > 199306 */


/*
 * These operating systems already take care of the problem for us.
 */
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__) || \
    defined(__sgi)
typedef u_int32_t       u_32_t;
# if defined(_KERNEL) && !defined(IPFILTER_LKM)
#  if defined(__NetBSD_Version__) && (__NetBSD_Version__ >= 104110000)
#   include "opt_inet.h"
#  endif
#  if defined(__FreeBSD_version) && (__FreeBSD_version >= 400000) && \
      !defined(KLD_MODULE)
#   include "opt_inet6.h"
#  endif
#  ifdef INET6
#   define USE_INET6
#  endif
# endif
#else
/*
 * Really, any arch where sizeof(long) != sizeof(int).
 */
# if defined(__alpha__) || defined(__alpha) || defined(_LP64)
typedef unsigned int    u_32_t;
# else
#  if SOLARIS2 >= 6
typedef	uint32_t	u_32_t;
#  else
typedef unsigned int	u_32_t;
#  endif
# endif
#endif /* __NetBSD__ || __OpenBSD__ || __FreeBSD__ || __sgi */

#ifdef	USE_INET6
# if defined(__NetBSD__) || defined(__OpenBSD__) || defined(__FreeBSD__)
#  include <netinet/ip6.h>
#  ifdef	_KERNEL
#   include <netinet6/ip6_var.h>
#  endif
typedef	struct ip6_hdr	ip6_t;
# endif
union	i6addr	{
	u_32_t	i6[4];
	struct	in_addr	in4;
	struct	in6_addr in6;
};
#else
union	i6addr	{
	u_32_t	i6[4];
	struct	in_addr	in4;
};
#endif

#define	IP6CMP(a,b)	bcmp((char *)&(a), (char *)&(b), sizeof(a))
#define	IP6EQ(a,b)	(bcmp((char *)&(a), (char *)&(b), sizeof(a)) == 0)
#define	IP6NEQ(a,b)	(bcmp((char *)&(a), (char *)&(b), sizeof(a)) != 0)

#ifndef	MAX
#define	MAX(a,b)	(((a) > (b)) ? (a) : (b))
#endif

/*
 * Security Options for Intenet Protocol (IPSO) as defined in RFC 1108.
 *
 * Basic Option
 *
 * 00000001   -   (Reserved 4)
 * 00111101   -   Top Secret
 * 01011010   -   Secret
 * 10010110   -   Confidential
 * 01100110   -   (Reserved 3)
 * 11001100   -   (Reserved 2)
 * 10101011   -   Unclassified
 * 11110001   -   (Reserved 1)
 */
#define	IPSO_CLASS_RES4		0x01
#define	IPSO_CLASS_TOPS		0x3d
#define	IPSO_CLASS_SECR		0x5a
#define	IPSO_CLASS_CONF		0x96
#define	IPSO_CLASS_RES3		0x66
#define	IPSO_CLASS_RES2		0xcc
#define	IPSO_CLASS_UNCL		0xab
#define	IPSO_CLASS_RES1		0xf1

#define	IPSO_AUTH_GENSER	0x80
#define	IPSO_AUTH_ESI		0x40
#define	IPSO_AUTH_SCI		0x20
#define	IPSO_AUTH_NSA		0x10
#define	IPSO_AUTH_DOE		0x08
#define	IPSO_AUTH_UN		0x06
#define	IPSO_AUTH_FTE		0x01

/*
 * IP option #defines
 */
/*#define	IPOPT_RR	7 */
#define	IPOPT_ZSU	10	/* ZSU */
#define	IPOPT_MTUP	11	/* MTUP */
#define	IPOPT_MTUR	12	/* MTUR */
#define	IPOPT_ENCODE	15	/* ENCODE */
/*#define	IPOPT_TS	68 */
#define	IPOPT_TR	82	/* TR */
/*#define	IPOPT_SECURITY	130 */
/*#define	IPOPT_LSRR	131 */
#define	IPOPT_E_SEC	133	/* E-SEC */
#define	IPOPT_CIPSO	134	/* CIPSO */
/*#define	IPOPT_SATID	136 */
#ifndef	IPOPT_SID
# define	IPOPT_SID	IPOPT_SATID
#endif
/*#define	IPOPT_SSRR	137 */
#define	IPOPT_ADDEXT	147	/* ADDEXT */
#define	IPOPT_VISA	142	/* VISA */
#define	IPOPT_IMITD	144	/* IMITD */
#define	IPOPT_EIP	145	/* EIP */
#define	IPOPT_FINN	205	/* FINN */


#if defined(__FreeBSD__) && (defined(KERNEL) || defined(_KERNEL))
# if __FreeBSD__ < 3
#  include <machine/spl.h>
# else
#  if __FreeBSD__ == 3
#   if defined(IPFILTER_LKM) && !defined(ACTUALLY_LKM_NOT_KERNEL)
#    define	ACTUALLY_LKM_NOT_KERNEL
#   endif
#  endif
# endif
#endif /* __FreeBSD__ && KERNEL */

/*
 * Build some macros and #defines to enable the same code to compile anywhere
 * Well, that's the idea, anyway :-)
 */
#if !SOLARIS || (SOLARIS2 < 6) || !defined(KERNEL)
# define	ATOMIC_INCL		ATOMIC_INC
# define	ATOMIC_INC64		ATOMIC_INC
# define	ATOMIC_INC32		ATOMIC_INC
# define	ATOMIC_INC16		ATOMIC_INC
# define	ATOMIC_DECL		ATOMIC_DEC
# define	ATOMIC_DEC64		ATOMIC_DEC
# define	ATOMIC_DEC32		ATOMIC_DEC
# define	ATOMIC_DEC16		ATOMIC_DEC
#endif
#ifdef KERNEL
# if SOLARIS
#  if SOLARIS2 >= 6
#   include <sys/atomic.h>
#   if SOLARIS2 == 6
#    define	ATOMIC_INCL(x)		atomic_add_long((uint32_t*)&(x), 1)
#    define	ATOMIC_DECL(x)		atomic_add_long((uint32_t*)&(x), -1)
#   else
#    define	ATOMIC_INCL(x)		atomic_add_long(&(x), 1)
#    define	ATOMIC_DECL(x)		atomic_add_long(&(x), -1)
#   endif
#   define	ATOMIC_INC64(x)		atomic_add_64((uint64_t*)&(x), 1)
#   define	ATOMIC_INC32(x)		atomic_add_32((uint32_t*)&(x), 1)
#   define	ATOMIC_INC16(x)		atomic_add_16((uint16_t*)&(x), 1)
#   define	ATOMIC_DEC64(x)		atomic_add_64((uint64_t*)&(x), -1)
#   define	ATOMIC_DEC32(x)		atomic_add_32((uint32_t*)&(x), -1)
#   define	ATOMIC_DEC16(x)		atomic_add_16((uint16_t*)&(x), -1)
#  else
#   define	ATOMIC_INC(x)		{ mutex_enter(&ipf_rw); (x)++; \
					  mutex_exit(&ipf_rw); }
#   define	ATOMIC_DEC(x)		{ mutex_enter(&ipf_rw); (x)--; \
					  mutex_exit(&ipf_rw); }
#  endif
#  define	MUTEX_ENTER(x)		mutex_enter(x)
#  if 1
#   define	KRWLOCK_T		krwlock_t
#   define	READ_ENTER(x)		rw_enter(x, RW_READER)
#   define	WRITE_ENTER(x)		rw_enter(x, RW_WRITER)
#   define	RW_UPGRADE(x)		{ if (rw_tryupgrade(x) == 0) { \
					      rw_exit(x); \
					      rw_enter(x, RW_WRITER); } \
					}
#   define	MUTEX_DOWNGRADE(x)	rw_downgrade(x)
#   define	RWLOCK_INIT(x, y, z)	rw_init((x), (y), RW_DRIVER, (z))
#   define	RWLOCK_EXIT(x)		rw_exit(x)
#   define	RW_DESTROY(x)		rw_destroy(x)
#  else
#   define	KRWLOCK_T		kmutex_t
#   define	READ_ENTER(x)		mutex_enter(x)
#   define	WRITE_ENTER(x)		mutex_enter(x)
#   define	MUTEX_DOWNGRADE(x)	;
#   define	RWLOCK_INIT(x, y, z)	mutex_init((x), (y), MUTEX_DRIVER, (z))
#   define	RWLOCK_EXIT(x)		mutex_exit(x)
#   define	RW_DESTROY(x)		mutex_destroy(x)
#  endif
#  define	MUTEX_INIT(x, y, z)	mutex_init((x), (y), MUTEX_DRIVER, (z))
#  define	MUTEX_DESTROY(x)	mutex_destroy(x)
#  define	MUTEX_EXIT(x)	mutex_exit(x)
#  define	MTOD(m,t)	(t)((m)->b_rptr)
#  define	IRCOPY(a,b,c)	copyin((a), (b), (c))
#  define	IWCOPY(a,b,c)	copyout((a), (b), (c))
#  define	IRCOPYPTR	ircopyptr
#  define	IWCOPYPTR	iwcopyptr
#  define	FREE_MB_T(m)	freemsg(m)
#  define	SPL_NET(x)	;
#  define	SPL_IMP(x)	;
#  undef	SPL_X
#  define	SPL_X(x)	;
#  ifdef sparc
#   define	ntohs(x)	(x)
#   define	ntohl(x)	(x)
#   define	htons(x)	(x)
#   define	htonl(x)	(x)
#  endif /* sparc */
#  define	KMALLOC(a,b)	(a) = (b)kmem_alloc(sizeof(*(a)), KM_NOSLEEP)
#  define	KMALLOCS(a,b,c)	(a) = (b)kmem_alloc((c), KM_NOSLEEP)
#  define	GET_MINOR(x)	getminor(x)
typedef	struct	qif	{
	struct	qif	*qf_next;
	ill_t	*qf_ill;
	kmutex_t	qf_lock;
	void	*qf_iptr;
	void	*qf_optr;
	queue_t	*qf_in;
	queue_t	*qf_out;
	struct	qinit	*qf_wqinfo;
	struct	qinit	*qf_rqinfo;
	struct	qinit	qf_wqinit;
	struct	qinit	qf_rqinit;
	mblk_t	*qf_m;	/* These three fields are for passing data up from */
	queue_t	*qf_q;	/* fr_qin and fr_qout to the packet processing. */
	size_t	qf_off;
	size_t	qf_len;	/* this field is used for in ipfr_fastroute */
	char	qf_name[8];
	/*
	 * in case the ILL has disappeared...
	 */
	size_t	qf_hl;	/* header length */
	int	qf_sap;
} qif_t;
extern	ill_t	*get_unit __P((char *, int));
#  define	GETUNIT(n, v)	get_unit(n, v)
#  define	IFNAME(x)	((ill_t *)x)->ill_name
# else /* SOLARIS */
#  if defined(__sgi)
#   define  hz HZ
#   include <sys/ksynch.h>
#   define	IPF_LOCK_PL	plhi
#   include <sys/sema.h>
#undef kmutex_t
typedef struct {
	lock_t *l;
	int pl;
} kmutex_t;
#   define	ATOMIC_INC(x)		{ MUTEX_ENTER(&ipf_rw); \
					  (x)++; MUTEX_EXIT(&ipf_rw); }
#   define	ATOMIC_DEC(x)		{ MUTEX_ENTER(&ipf_rw); \
					  (x)--; MUTEX_EXIT(&ipf_rw); }
#   define	MUTEX_ENTER(x)		(x)->pl = LOCK((x)->l, IPF_LOCK_PL);
#   define	KRWLOCK_T		kmutex_t
#   define	READ_ENTER(x)		MUTEX_ENTER(x)
#   define	WRITE_ENTER(x)		MUTEX_ENTER(x)
#   define	RW_UPGRADE(x)		;
#   define	MUTEX_DOWNGRADE(x)	;
#   define	RWLOCK_EXIT(x)		MUTEX_EXIT(x)
#   define	MUTEX_EXIT(x)		UNLOCK((x)->l, (x)->pl);
#   define	MUTEX_INIT(x,y,z)	(x).l = LOCK_ALLOC((uchar_t)-1, IPF_LOCK_PL, (lkinfo_t *)-1, KM_NOSLEEP)
#   define	MUTEX_DESTROY(x)	LOCK_DEALLOC((x).l)
#  else /* __sgi */
#   define	ATOMIC_INC(x)		(x)++
#   define	ATOMIC_DEC(x)		(x)--
#   define	MUTEX_ENTER(x)		;
#   define	READ_ENTER(x)		;
#   define	WRITE_ENTER(x)		;
#   define	RW_UPGRADE(x)		;
#   define	MUTEX_DOWNGRADE(x)	;
#   define	RWLOCK_EXIT(x)		;
#   define	MUTEX_EXIT(x)		;
#   define	MUTEX_INIT(x,y,z)	;
#   define	MUTEX_DESTROY(x)	;
#  endif /* __sgi */
#  ifndef linux
#   define	FREE_MB_T(m)	m_freem(m)
#   define	MTOD(m,t)	mtod(m,t)
#   define	IRCOPY(a,b,c)	(bcopy((a), (b), (c)), 0)
#   define	IWCOPY(a,b,c)	(bcopy((a), (b), (c)), 0)
#   define	IRCOPYPTR	ircopyptr
#   define	IWCOPYPTR	iwcopyptr
#  endif /* !linux */
# endif /* SOLARIS */

# ifdef sun
#  if !SOLARIS
#   include	<sys/kmem_alloc.h>
#   define	GETUNIT(n, v)	ifunit(n, IFNAMSIZ)
#   define	IFNAME(x)	((struct ifnet *)x)->if_name
#  endif
# else
#  ifndef	linux
#   define	GETUNIT(n, v)	ifunit(n)
#   if (defined(NetBSD) && (NetBSD <= 1991011) && (NetBSD >= 199606)) || \
        (defined(OpenBSD) && (OpenBSD >= 199603))
#    define	IFNAME(x)	((struct ifnet *)x)->if_xname
#   else
#    define	IFNAME(x)	((struct ifnet *)x)->if_name
#   endif
#  endif
# endif /* sun */

# if defined(sun) && !defined(linux) || defined(__sgi)
#  define	UIOMOVE(a,b,c,d)	uiomove((caddr_t)a,b,c,d)
#  define	SLEEP(id, n)	sleep((id), PZERO+1)
#  define	WAKEUP(id)	wakeup(id)
#  define	KFREE(x)	kmem_free((char *)(x), sizeof(*(x)))
#  define	KFREES(x,s)	kmem_free((char *)(x), (s))
#  if !SOLARIS
extern	void	m_copydata __P((struct mbuf *, int, int, caddr_t));
extern	void	m_copyback __P((struct mbuf *, int, int, caddr_t));
#  endif
#  ifdef __sgi
#   include <sys/kmem.h>
#   include <sys/ddi.h>
#   define	KMALLOC(a,b)	(a) = (b)kmem_alloc(sizeof(*(a)), KM_NOSLEEP)
#   define	KMALLOCS(a,b,c)	(a) = (b)kmem_alloc((c), KM_NOSLEEP)
#   define	GET_MINOR(x)	getminor(x)
#  else
#   if !SOLARIS
#    define	KMALLOC(a,b)	(a) = (b)new_kmem_alloc(sizeof(*(a)), \
							KMEM_NOSLEEP)
#    define	KMALLOCS(a,b,c)	(a) = (b)new_kmem_alloc((c), KMEM_NOSLEEP)
#   endif /* SOLARIS */
#  endif /* __sgi */
# endif /* sun && !linux */
# ifndef	GET_MINOR
#  define	GET_MINOR(x)	minor(x)
# endif
# if (BSD >= 199306) || defined(__FreeBSD__)
#  include <vm/vm.h>
#  if !defined(__FreeBSD__) || (defined (__FreeBSD__) && __FreeBSD__>=3)
#   include <vm/vm_extern.h>
#   include <sys/proc.h>
extern	vm_map_t	kmem_map;
#  else /* !__FreeBSD__ || (__FreeBSD__ && __FreeBSD__>=3) */
#   include <vm/vm_kern.h>
#  endif /* !__FreeBSD__ || (__FreeBSD__ && __FreeBSD__>=3) */
#  ifdef	M_PFIL
#   define	KMALLOC(a, b)	MALLOC((a), b, sizeof(*(a)), M_PFIL, M_NOWAIT)
#   define	KMALLOCS(a, b, c)	MALLOC((a), b, (c), M_PFIL, M_NOWAIT)
#   define	KFREE(x)	FREE((x), M_PFIL)
#   define	KFREES(x,s)	FREE((x), M_PFIL)
#  else
#   define	KMALLOC(a, b)	MALLOC((a), b, sizeof(*(a)), M_TEMP, M_NOWAIT)
#   define	KMALLOCS(a, b, c)	MALLOC((a), b, (c), M_TEMP, M_NOWAIT)
#   define	KFREE(x)	FREE((x), M_TEMP)
#   define	KFREES(x,s)	FREE((x), M_TEMP)
#  endif /* M_PFIL */
#  define	UIOMOVE(a,b,c,d)	uiomove(a,b,d)
#  define	SLEEP(id, n)	tsleep((id), PPAUSE|PCATCH, n, 0)
#  define	WAKEUP(id)	wakeup(id)
# endif /* BSD */
# if defined(NetBSD) && NetBSD <= 1991011 && NetBSD >= 199407
#  define	SPL_NET(x)	x = splsoftnet()
#  define	SPL_X(x)	(void) splx(x)
# else
#  if !SOLARIS && !defined(linux)
#   define	SPL_IMP(x)	x = splimp()
#   define	SPL_NET(x)	x = splnet()
#   define	SPL_X(x)	(void) splx(x)
#  endif
# endif /* NetBSD && NetBSD <= 1991011 && NetBSD >= 199407 */
# define	PANIC(x,y)	if (x) panic y
#else /* KERNEL */
# define	SLEEP(x,y)	;
# define	WAKEUP(x)	;
# define	PANIC(x,y)	;
# define	ATOMIC_INC(x)	(x)++
# define	ATOMIC_DEC(x)	(x)--
# define	MUTEX_ENTER(x)	;
# define	READ_ENTER(x)	;
# define	MUTEX_INIT(x,y,z)	;
# define	MUTEX_DESTROY(x)	;
# define	WRITE_ENTER(x)	;
# define	RW_UPGRADE(x)	;
# define	MUTEX_DOWNGRADE(x)	;
# define	RWLOCK_EXIT(x)	;
# define	MUTEX_EXIT(x)	;
# define	SPL_NET(x)	;
# define	SPL_IMP(x)	;
# undef		SPL_X
# define	SPL_X(x)	;
# define	KMALLOC(a,b)	(a) = (b)malloc(sizeof(*a))
# define	KMALLOCS(a,b,c)	(a) = (b)malloc(c)
# define	KFREE(x)	free(x)
# define	KFREES(x,s)	free(x)
# define	GETUNIT(x, v)	get_unit(x,v)
# define	IRCOPY(a,b,c)	(bcopy((a), (b), (c)), 0)
# define	IWCOPY(a,b,c)	(bcopy((a), (b), (c)), 0)
# define	IRCOPYPTR	ircopyptr
# define	IWCOPYPTR	iwcopyptr
#endif /* KERNEL */

#if SOLARIS
typedef mblk_t mb_t;
# if SOLARIS2 >= 7
#  ifdef lint
#   define ALIGN32(ptr)    (ptr ? 0L : 0L)
#   define ALIGN16(ptr)    (ptr ? 0L : 0L)
#  else
#   define ALIGN32(ptr)    (ptr)
#   define ALIGN16(ptr)    (ptr)
#  endif
# endif
#else
# ifdef	linux
#  ifndef kernel
typedef struct mb {
	struct mb *next;
	u_int len;
	u_char *data;
} mb_t;
#  else
typedef struct sk_buff mb_t;
#  endif
# else
typedef struct mbuf mb_t;
# endif
#endif /* SOLARIS */

#if defined(linux) || defined(__sgi)
/*
 * These #ifdef's are here mainly for linux, but who knows, they may
 * not be in other places or maybe one day linux will grow up and some
 * of these will turn up there too.
 */
#ifndef	ICMP_MINLEN
# define	ICMP_MINLEN	8
#endif
#ifndef	ICMP_UNREACH
# define	ICMP_UNREACH	ICMP_DEST_UNREACH
#endif
#ifndef	ICMP_SOURCEQUENCH
# define	ICMP_SOURCEQUENCH	ICMP_SOURCE_QUENCH
#endif
#ifndef	ICMP_TIMXCEED
# define	ICMP_TIMXCEED	ICMP_TIME_EXCEEDED
#endif
#ifndef	ICMP_PARAMPROB
# define	ICMP_PARAMPROB	ICMP_PARAMETERPROB
#endif
#ifndef ICMP_TSTAMP
# define	ICMP_TSTAMP	ICMP_TIMESTAMP
#endif
#ifndef ICMP_TSTAMPREPLY
# define	ICMP_TSTAMPREPLY	ICMP_TIMESTAMPREPLY
#endif
#ifndef ICMP_IREQ
# define	ICMP_IREQ	ICMP_INFO_REQUEST
#endif
#ifndef ICMP_IREQREPLY
# define	ICMP_IREQREPLY	ICMP_INFO_REPLY
#endif
#ifndef	ICMP_MASKREQ
# define	ICMP_MASKREQ	ICMP_ADDRESS
#endif
#ifndef ICMP_MASKREPLY
# define	ICMP_MASKREPLY	ICMP_ADDRESSREPLY
#endif
#ifndef	IPVERSION
# define	IPVERSION	4
#endif
#ifndef	IPOPT_MINOFF
# define	IPOPT_MINOFF	4
#endif
#ifndef	IPOPT_COPIED
# define	IPOPT_COPIED(x)	((x)&0x80)
#endif
#ifndef	IPOPT_EOL
# define	IPOPT_EOL	0
#endif
#ifndef	IPOPT_NOP
# define	IPOPT_NOP	1
#endif
#ifndef	IP_MF
# define	IP_MF	((u_short)0x2000)
#endif
#ifndef	ETHERTYPE_IP
# define	ETHERTYPE_IP	((u_short)0x0800)
#endif
#ifndef	TH_FIN
# define	TH_FIN	0x01
#endif
#ifndef	TH_SYN
# define	TH_SYN	0x02
#endif
#ifndef	TH_RST
# define	TH_RST	0x04
#endif
#ifndef	TH_PUSH
# define	TH_PUSH	0x08
#endif
#ifndef	TH_ACK
# define	TH_ACK	0x10
#endif
#ifndef	TH_URG
# define	TH_URG	0x20
#endif
#ifndef	IPOPT_EOL
# define	IPOPT_EOL	0
#endif
#ifndef	IPOPT_NOP
# define	IPOPT_NOP	1
#endif
#ifndef	IPOPT_RR
# define	IPOPT_RR	7
#endif
#ifndef	IPOPT_TS
# define	IPOPT_TS	68
#endif
#ifndef	IPOPT_SECURITY
# define	IPOPT_SECURITY	130
#endif
#ifndef	IPOPT_LSRR
# define	IPOPT_LSRR	131
#endif
#ifndef	IPOPT_SATID
# define	IPOPT_SATID	136
#endif
#ifndef	IPOPT_SSRR
# define	IPOPT_SSRR	137
#endif
#ifndef	IPOPT_SECUR_UNCLASS
# define	IPOPT_SECUR_UNCLASS	((u_short)0x0000)
#endif
#ifndef	IPOPT_SECUR_CONFID
# define	IPOPT_SECUR_CONFID	((u_short)0xf135)
#endif
#ifndef	IPOPT_SECUR_EFTO
# define	IPOPT_SECUR_EFTO	((u_short)0x789a)
#endif
#ifndef	IPOPT_SECUR_MMMM
# define	IPOPT_SECUR_MMMM	((u_short)0xbc4d)
#endif
#ifndef	IPOPT_SECUR_RESTR
# define	IPOPT_SECUR_RESTR	((u_short)0xaf13)
#endif
#ifndef	IPOPT_SECUR_SECRET
# define	IPOPT_SECUR_SECRET	((u_short)0xd788)
#endif
#ifndef IPOPT_SECUR_TOPSECRET
# define	IPOPT_SECUR_TOPSECRET	((u_short)0x6bc5)
#endif
#ifndef IPOPT_OLEN
# define	IPOPT_OLEN	1
#endif
#endif /* linux || __sgi */

#ifdef	linux
#include <linux/in_systm.h>
/*
 * TCP States
 */
#define	TCPS_CLOSED		0	/* closed */
#define	TCPS_LISTEN		1	/* listening for connection */
#define	TCPS_SYN_SENT		2	/* active, have sent syn */
#define	TCPS_SYN_RECEIVED	3	/* have send and received syn */
/* states < TCPS_ESTABLISHED are those where connections not established */
#define	TCPS_ESTABLISHED	4	/* established */
#define	TCPS_CLOSE_WAIT		5	/* rcvd fin, waiting for close */
/* states > TCPS_CLOSE_WAIT are those where user has closed */
#define	TCPS_FIN_WAIT_1		6	/* have closed, sent fin */
#define	TCPS_CLOSING		7	/* closed xchd FIN; await FIN ACK */
#define	TCPS_LAST_ACK		8	/* had fin and close; await FIN ACK */
/* states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN */
#define	TCPS_FIN_WAIT_2		9	/* have closed, fin is acked */
#define	TCPS_TIME_WAIT		10	/* in 2*msl quiet wait after close */

/*
 * file flags.
 */
#ifdef WRITE
#define	FWRITE	WRITE
#define	FREAD	READ
#else
#define	FWRITE	_IOC_WRITE
#define	FREAD	_IOC_READ
#endif
/*
 * mbuf related problems.
 */
#define	mtod(m,t)	(t)((m)->data)
#define	m_len		len
#define	m_next		next

#ifdef	IP_DF
#undef	IP_DF
#endif
#define	IP_DF		0x4000

typedef	struct	{
	__u16	th_sport;
	__u16	th_dport;
	__u32	th_seq;
	__u32	th_ack;
# if defined(__i386__) || defined(__MIPSEL__) || defined(__alpha__) ||\
    defined(vax)
	__u8	th_res:4;
	__u8	th_off:4;
#else
	__u8	th_off:4;
	__u8	th_res:4;
#endif
	__u8	th_flags;
	__u16	th_win;
	__u16	th_sum;
	__u16	th_urp;
} tcphdr_t;

typedef	struct	{
	__u16	uh_sport;
	__u16	uh_dport;
	__u16	uh_ulen;
	__u16	uh_sum;
} udphdr_t;

typedef	struct	{
# if defined(__i386__) || defined(__MIPSEL__) || defined(__alpha__) ||\
    defined(vax)
	__u8	ip_hl:4;
	__u8	ip_v:4;
# else
	__u8	ip_v:4;
	__u8	ip_hl:4;
# endif
	__u8	ip_tos;
	__u16	ip_len;
	__u16	ip_id;
	__u16	ip_off;
	__u8	ip_ttl;
	__u8	ip_p;
	__u16	ip_sum;
	struct	in_addr	ip_src;
	struct	in_addr	ip_dst;
} ip_t;

/*
 * Structure of an icmp header.
 */
typedef struct icmp {
	__u8	icmp_type;		/* type of message, see below */
	__u8	icmp_code;		/* type sub code */
	__u16	icmp_cksum;		/* ones complement cksum of struct */
	union {
		__u8	ih_pptr;		/* ICMP_PARAMPROB */
		struct	in_addr	ih_gwaddr;	/* ICMP_REDIRECT */
		struct	ih_idseq {
			__u16	icd_id;
			__u16	icd_seq;
		} ih_idseq;
		int ih_void;
	} icmp_hun;
# define	icmp_pptr	icmp_hun.ih_pptr
# define	icmp_gwaddr	icmp_hun.ih_gwaddr
# define	icmp_id		icmp_hun.ih_idseq.icd_id
# define	icmp_seq	icmp_hun.ih_idseq.icd_seq
# define	icmp_void	icmp_hun.ih_void
	union {
		struct id_ts {
			n_time its_otime;
			n_time its_rtime;
			n_time its_ttime;
		} id_ts;
		struct id_ip  {
			ip_t idi_ip;
			/* options and then 64 bits of data */
		} id_ip;
		u_long	id_mask;
		char	id_data[1];
	} icmp_dun;
# define	icmp_otime	icmp_dun.id_ts.its_otime
# define	icmp_rtime	icmp_dun.id_ts.its_rtime
# define	icmp_ttime	icmp_dun.id_ts.its_ttime
# define	icmp_ip		icmp_dun.id_ip.idi_ip
# define	icmp_mask	icmp_dun.id_mask
# define	icmp_data	icmp_dun.id_data
} icmphdr_t;

# ifndef LINUX_IPOVLY
#  define LINUX_IPOVLY
struct ipovly {
	caddr_t	ih_next, ih_prev;	/* for protocol sequence q's */
	u_char	ih_x1;			/* (unused) */
	u_char	ih_pr;			/* protocol */
	short	ih_len;			/* protocol length */
	struct	in_addr ih_src;		/* source internet address */
	struct	in_addr ih_dst;		/* destination internet address */
};
# endif

typedef struct  {
	__u8	ether_dhost[6];
	__u8	ether_shost[6];
	__u16	ether_type;
} ether_header_t;

typedef	struct	uio	{
	int	uio_resid;
	int	uio_rw;
	caddr_t	uio_buf;
} uio_t;

# define	UIO_READ	0
# define	UIO_WRITE	1
# define	UIOMOVE(a, b, c, d)	uiomove(a,b,c,d)

/*
 * For masking struct ifnet onto struct device
 */
# define	if_name	name

# ifdef	KERNEL
#  define	GETUNIT(x, v)	dev_get(x)
#  define	FREE_MB_T(m)	kfree_skb(m, FREE_WRITE)
#  define	uniqtime	do_gettimeofday
#  undef INT_MAX
#  undef UINT_MAX
#  undef LONG_MAX
#  undef ULONG_MAX
#  include <linux/netdevice.h>
#  define	SPL_X(x)
#  define	SPL_NET(x)
#  define	SPL_IMP(x)
 
#  define	bcmp(a,b,c)	memcmp(a,b,c)
#  define	bcopy(a,b,c)	memcpy(b,a,c)
#  define	bzero(a,c)	memset(a,0,c)

#  define	UNITNAME(n)	dev_get((n))

#  define	KMALLOC(a,b)	(a) = (b)kmalloc(sizeof(*(a)), GFP_ATOMIC)
#  define	KMALLOCS(a,b,c)	(a) = (b)kmalloc((c), GFP_ATOMIC)
#  define	KFREE(x)	kfree_s((x), sizeof(*(x)))
#  define	KFREES(x,s)	kfree_s((x), (s))
#define IRCOPY(const void *a, void *b, size_t c)	{ \
	int error; \

	error = verify_area(VERIFY_READ, a ,c); \
	if (!error) \
		memcpy_fromfs(b, a, c); \
	return error; \
}
static inline int IWCOPY(const void *a, void *b, size_t c)
{
	int error;

	error = verify_area(VERIFY_WRITE, b, c);
	if (!error)
		memcpy_tofs(b, a, c);
	return error;
}
static inline int IRCOPYPTR(const void *a, void *b, size_t c) {
	caddr_t ca;
	int	error;

	error = verify_area(VERIFY_READ, a ,sizeof(ca));
	if (!error) {
		memcpy_fromfs(ca, a, sizeof(ca));
		error = verify_area(VERIFY_READ, ca , c);
		if (!error)
			memcpy_fromfs(b, ca, c);
	}
	return error;
}
static inline int IWCOPYPTR(const void *a, void *b, size_t c) {
	caddr_t ca;
	int	error;


	error = verify_area(VERIFY_READ, b ,sizeof(ca));
	if (!error) {
		memcpy_fromfs(ca, b, sizeof(ca));
		error = verify_area(VERIFY_WRITE, ca, c);
		if (!error)
			memcpy_tofs(ca, a, c);
	}
	return error;
}
# else
#  define	__KERNEL__
#  undef INT_MAX
#  undef UINT_MAX
#  undef LONG_MAX
#  undef ULONG_MAX
#  define	s8 __s8
#  define	u8 __u8
#  define	s16 __s16
#  define	u16 __u16
#  define	s32 __s32
#  define	u32 __u32
#  include <linux/netdevice.h>
#  undef	__KERNEL__
# endif
# define	ifnet	device
#else
typedef	struct	tcphdr	tcphdr_t;
typedef	struct	udphdr	udphdr_t;
typedef	struct	icmp	icmphdr_t;
typedef	struct	ip	ip_t;
typedef	struct	ether_header	ether_header_t;
#endif /* linux */
typedef	struct	tcpiphdr	tcpiphdr_t;

#if defined(hpux) || defined(linux)
struct	ether_addr	{
	char	ether_addr_octet[6];
};
#endif

/*
 * XXX - This is one of those *awful* hacks which nobody likes
 */
#ifdef	ultrix
#define	A_A
#else
#define	A_A	&
#endif

#define	TCPF_ALL	(TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG)

#ifndef	ICMP_ROUTERADVERT
# define	ICMP_ROUTERADVERT	9
#endif
#ifndef	ICMP_ROUTERSOLICIT
# define	ICMP_ROUTERSOLICIT	10
#endif
#undef	ICMP_MAX_UNREACH
#define	ICMP_MAX_UNREACH	14
#undef	ICMP_MAXTYPE
#define	ICMP_MAXTYPE		18
/*
 * ICMP error replies have an IP header (20 bytes), 8 bytes of ICMP data,
 * another IP header and then 64 bits of data, totalling 56.  Of course,
 * the last 64 bits is dependant on that being available.
 */
#define	ICMPERR_ICMPHLEN	8
#define	ICMPERR_IPICMPHLEN	(20 + 8)
#define	ICMPERR_MINPKTLEN	(20 + 8 + 20)
#define	ICMPERR_MAXPKTLEN	(20 + 8 + 20 + 8)
#define	ICMP6ERR_MINPKTLEN	(20 + 8)

#endif	/* __IP_COMPAT_H__ */

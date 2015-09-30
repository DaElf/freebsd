/*	$NetBSD: svc_generic.c,v 1.3 2000/07/06 03:10:35 christos Exp $	*/

/*-
 * Copyright (c) 2009, Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice, 
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice, 
 *   this list of conditions and the following disclaimer in the documentation 
 *   and/or other materials provided with the distribution.
 * - Neither the name of Sun Microsystems, Inc. nor the names of its 
 *   contributors may be used to endorse or promote products derived 
 *   from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 1986-1991 by Sun Microsystems Inc.
 */

#if defined(LIBC_SCCS) && !defined(lint)
#ident	"@(#)svc_generic.c	1.19	94/04/24 SMI" 
static char sccsid[] = "@(#)svc_generic.c 1.21 89/02/28 Copyr 1988 Sun Micro";
#endif
#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

/*
 * svc_generic.c, Server side for RPC.
 *
 */

#include "namespace.h"
#include "reentrant.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rpc/rpc.h>
#include <rpc/nettype.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include "un-namespace.h"

#include "rpc_com.h"
#include "mt_misc.h"

extern int __svc_vc_setflag(SVCXPRT *, int);

/*
 * The highest level interface for server creation.
 * It tries for all the nettokens in that particular class of token
 * and returns the number of handles it can create and/or find.
 *
 * It creates a link list of all the handles it could create.
 * If svc_create() is called multiple times, it uses the handle
 * created earlier instead of creating a new handle every time.
 *
 * prognum - Program number
 * versnum - Version number
 * nettype - Networktype token
 */
int
svc_create(void (*dispatch)(struct svc_req *, SVCXPRT *),
    rpcprog_t prognum, rpcvers_t versnum, const char *nettype)
{
	struct xlist {
		SVCXPRT *xprt;		/* Server handle */
		struct xlist *next;	/* Next item */
	} *l;
	static struct xlist *xprtlist;	/* A link list of all the handles */
	int num = 0;
	SVCXPRT *xprt;
	struct netconfig *nconf;
	void *handle;

/* VARIABLES PROTECTED BY xprtlist_lock: xprtlist */

	if ((handle = __rpc_setconf(nettype)) == NULL) {
		warnx("svc_create: unknown protocol");
		return (0);
	}
	while ((nconf = __rpc_getconf(handle)) != NULL) {
		mutex_lock(&xprtlist_lock);
		for (l = xprtlist; l; l = l->next) {
			if (strcmp(l->xprt->xp_netid, nconf->nc_netid) == 0) {
				/* Found an old one, use it */
				(void) rpcb_unset(prognum, versnum, nconf);
				if (svc_reg(l->xprt, prognum, versnum,
					dispatch, nconf) == FALSE)
					warnx(
		"svc_create: could not register prog %u vers %u on %s",
					(unsigned)prognum, (unsigned)versnum,
					 nconf->nc_netid);
				else
					num++;
				break;
			}
		}
		if (l == NULL) {
			/* It was not found. Now create a new one */
			xprt = svc_tp_create(dispatch, prognum, versnum, nconf);
			if (xprt) {
				l = (struct xlist *)malloc(sizeof (*l));
				if (l == NULL) {
					warnx("svc_create: no memory");
					mutex_unlock(&xprtlist_lock);
					return (0);
				}
				l->xprt = xprt;
				l->next = xprtlist;
				xprtlist = l;
				num++;
			}
		}
		mutex_unlock(&xprtlist_lock);
	}
	__rpc_endconf(handle);
	/*
	 * In case of num == 0; the error messages are generated by the
	 * underlying layers; and hence not needed here.
	 */
	return (num);
}

/*
 * The high level interface to svc_tli_create().
 * It tries to create a server for "nconf" and registers the service
 * with the rpcbind. It calls svc_tli_create();
 *
 * prognum - Program number
 * versnum - Version number
 * ncofn   - Netconfig structure for the network
 */
SVCXPRT *
svc_tp_create(void (*dispatch)(struct svc_req *, SVCXPRT *),
    rpcprog_t prognum, rpcvers_t versnum, const struct netconfig *nconf)
{
	SVCXPRT *xprt;

	if (nconf == NULL) {
		warnx(
	"svc_tp_create: invalid netconfig structure for prog %u vers %u",
				(unsigned)prognum, (unsigned)versnum);
		return (NULL);
	}
	xprt = svc_tli_create(RPC_ANYFD, nconf, NULL, 0, 0);
	if (xprt == NULL) {
		return (NULL);
	}
	/*LINTED const castaway*/
	(void) rpcb_unset(prognum, versnum, (struct netconfig *) nconf);
	if (svc_reg(xprt, prognum, versnum, dispatch, nconf) == FALSE) {
		warnx(
		"svc_tp_create: Could not register prog %u vers %u on %s",
				(unsigned)prognum, (unsigned)versnum,
				nconf->nc_netid);
		SVC_DESTROY(xprt);
		return (NULL);
	}
	return (xprt);
}

/*
 * If fd is RPC_ANYFD, then it opens a fd for the given transport
 * provider (nconf cannot be NULL then). If the t_state is T_UNBND and
 * bindaddr is NON-NULL, it performs a t_bind using the bindaddr. For
 * NULL bindadr and Connection oriented transports, the value of qlen
 * is set to 8.
 *
 * If sendsz or recvsz are zero, their default values are chosen.
 *
 * fd       - Connection end point
 * nconf    - Netconfig struct for nettoken
 * bindaddr - Local bind address
 * sendsz   - Max sendsize
 * recvxz   - Max recvsize
 */
SVCXPRT *
svc_tli_create(int fd, const struct netconfig *nconf,
    const struct t_bind *bindaddr, u_int sendsz, u_int recvsz)
{
	SVCXPRT *xprt = NULL;		/* service handle */
	bool_t madefd = FALSE;		/* whether fd opened here  */
	struct __rpc_sockinfo si;
	struct sockaddr_storage ss;
	socklen_t slen;

	if (fd == RPC_ANYFD) {
		if (nconf == NULL) {
			warnx("svc_tli_create: invalid netconfig");
			return (NULL);
		}
		fd = __rpc_nconf2fd(nconf);
		if (fd == -1) {
			warnx(
			    "svc_tli_create: could not open connection for %s",
					nconf->nc_netid);
			return (NULL);
		}
		__rpc_nconf2sockinfo(nconf, &si);
		madefd = TRUE;
	} else {
		/*
		 * It is an open descriptor. Get the transport info.
		 */
		if (!__rpc_fd2sockinfo(fd, &si)) {
			warnx(
		"svc_tli_create: could not get transport information");
			return (NULL);
		}
	}

	/*
	 * If the fd is unbound, try to bind it.
	 */
	if (madefd || !__rpc_sockisbound(fd)) {
		if (bindaddr == NULL) {
			if (bindresvport(fd, NULL) < 0) {
				memset(&ss, 0, sizeof ss);
				ss.ss_family = si.si_af;
				ss.ss_len = si.si_alen;
				if (_bind(fd, (struct sockaddr *)(void *)&ss,
				    (socklen_t)si.si_alen) < 0) {
					warnx(
			"svc_tli_create: could not bind to anonymous port");
					goto freedata;
				}
			}
			_listen(fd, SOMAXCONN);
		} else {
			if (_bind(fd,
			    (struct sockaddr *)bindaddr->addr.buf,
			    (socklen_t)si.si_alen) < 0) {
				warnx(
		"svc_tli_create: could not bind to requested address");
				goto freedata;
			}
			_listen(fd, (int)bindaddr->qlen);
		}
			
	}
	/*
	 * call transport specific function.
	 */
	switch (si.si_socktype) {
		case SOCK_STREAM:
			slen = sizeof ss;
			if (_getpeername(fd, (struct sockaddr *)(void *)&ss, &slen)
			    == 0) {
				/* accepted socket */
				xprt = svc_fd_create(fd, sendsz, recvsz);
			} else
				xprt = svc_vc_create(fd, sendsz, recvsz);
			if (!nconf || !xprt)
				break;
#if 0
			/* XXX fvdl */
			if (strcmp(nconf->nc_protofmly, "inet") == 0 ||
			    strcmp(nconf->nc_protofmly, "inet6") == 0)
				(void) __svc_vc_setflag(xprt, TRUE);
#endif
			break;
		case SOCK_DGRAM:
			xprt = svc_dg_create(fd, sendsz, recvsz);
			break;
		default:
			warnx("svc_tli_create: bad service type");
			goto freedata;
	}

	if (xprt == NULL)
		/*
		 * The error messages here are spitted out by the lower layers:
		 * svc_vc_create(), svc_fd_create() and svc_dg_create().
		 */
		goto freedata;

	/* Fill in type of service */
	xprt->xp_type = __rpc_socktype2seman(si.si_socktype);

	if (nconf) {
		xprt->xp_netid = strdup(nconf->nc_netid);
		xprt->xp_tp = strdup(nconf->nc_device);
	}
	return (xprt);

freedata:
	if (madefd)
		(void)_close(fd);
	if (xprt) {
		if (!madefd) /* so that svc_destroy doesnt close fd */
			xprt->xp_fd = RPC_ANYFD;
		SVC_DESTROY(xprt);
	}
	return (NULL);
}

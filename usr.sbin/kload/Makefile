# $FreeBSD$

PROG=	kload
SRCS=	kload.c
NO_MAN=

#DPADD+=	${LIBVMMAPI}
#LDADD+=	-lvmmapi

WARNS?=	3

CFLAGS+=-g3
CFLAGS+=-I${.CURDIR}/../../sys/boot/userboot
CFLAGS+=-I${.CURDIR}/../../sys

.include <bsd.prog.mk>

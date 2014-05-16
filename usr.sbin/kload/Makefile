# $FreeBSD$

PROG=	kload
SRCS=	kload.c
MAN=	kload.8

WARNS?=	3

CFLAGS+=-I${.CURDIR}/../../sys/boot/userboot
CFLAGS+=-I${.CURDIR}/../../sys

.include <bsd.prog.mk>

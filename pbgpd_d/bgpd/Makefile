#	$OpenBSD: Makefile,v 1.28 2009/06/25 14:14:54 deraadt Exp $

PROG=	bgpd
SRCS=	bgpd.c buffer.c session.c log.c parse.y config.c imsg.c \
	rde.c rde_rib.c rde_decide.c rde_prefix.c mrt.c kroute.c \
	control.c pfkey.c rde_update.c rde_attr.c printconf.c \
	rde_filter.c pftable.c name2id.c util.c carp.c timer.c \
	pbgpd.c
CFLAGS+= -Wall -I${.CURDIR}
CFLAGS+= -I/usr/local/include
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I/usr/local/include -I/usr/local/include/db4 -I/usr/local/include/pbgp -I/usr/local/include/pbc
CPPFLAGS+=-DPBGPD

LDADD+= -L. -L/usr/local/lib/ -lpbgp -lgmp -lpbc -lpbgp

YFLAGS=
MAN= bgpd.8 bgpd.conf.5

.include <bsd.prog.mk>

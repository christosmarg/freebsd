PACKAGE=	iscsi
PROG=		iscsictl
SRCS=		iscsictl.c periphs.c parse.y token.l y.tab.h
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-I${SRCTOP}/sys/dev/iscsi
MAN=		iscsi.conf.5 iscsictl.8

LIBADD=		util xo

YFLAGS+=	-v
LFLAGS+=	-i
CLEANFILES=	y.tab.c y.tab.h y.output

NO_WMISSING_VARIABLE_DECLARATIONS=

.include <bsd.prog.mk>

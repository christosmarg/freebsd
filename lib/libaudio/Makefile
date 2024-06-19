LIB=		audio
SRCS=		${LIB}.c
INCS=		${LIB}.h
MAN=		${LIB}.3
VERSION_DEF=	${LIBCSRCDIR}/Versions.def
SYMBOL_MAPS=	${.CURDIR}/Symbol.map
LDFLAGS+=	-lmixer -lnv

MLINKS+=	audio.3 audio_open.3
MLINKS+=	audio.3 audio_close.3

.include <bsd.lib.mk>

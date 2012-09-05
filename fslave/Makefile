
PROG=		fslave
SRCS=		main.c
TOP_DIR=	..
CFLAGS=		-I${TOP_DIR}/include
LIB_DIR=	${TOP_DIR}/lib
LDADD =		${LIB_DIR}/atoi_or_die/libatoi_or_die.a ${LIB_DIR}/io/libio.a \
		${LIB_DIR}/encode/libencode.a
WITHOUT_MAN=	yes

.include <bsd.prog.mk>


PROG=		fslave
SRCS=		main.c
TOP_DIR=	..
CFLAGS=		-I${TOP_DIR}/include
LIB_DIR=	${TOP_DIR}/lib
LDADD =		${LIB_DIR}/private/libprivate.a ${LIB_DIR}/encode/libencode.a
WITHOUT_MAN=	yes

.include <bsd.prog.mk>


PROG=		fslave
SRCS=		main.c
TOP_DIR=	..
CFLAGS=		-I${TOP_DIR}/include
LIB_DIR=	${TOP_DIR}/lib
LDADD =		${LIB_DIR}/atoi_or_die/libatoi_or_die.a ${LIB_DIR}/io/libio.a \
		${LIB_DIR}/encode/libencode.a ${LIB_DIR}/die/libdie.a \
		${LIB_DIR}/log/liblog.a ${LIB_DIR}/command/libcommand.a
WITHOUT_MAN=	yes

.include "${TOP_DIR}/Makefile.common"
.include <bsd.prog.mk>

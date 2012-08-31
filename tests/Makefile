
PROG=		tester
SRCS=		main.c
WITHOUT_MAN=	yes
TOP_DIR=	..
CFLAGS=		-I${TOP_DIR}/include
LIB_DIR=	${TOP_DIR}/lib
LDADD =		${LIB_DIR}/start_slave/libstart_slave.a \
		${LIB_DIR}/start_master/libstart_master.a \
		${LIB_DIR}/private/libprivate.a

install:

.include <bsd.prog.mk>

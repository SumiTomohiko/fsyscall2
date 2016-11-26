
PROG=		tester
SRCS=		main.c
WITHOUT_MAN=	yes
TOP_DIR=	../..
CFLAGS=		-I${TOP_DIR}/include
LIB_DIR=	${TOP_DIR}/lib
LDADD =		-lssl ${LIB_DIR}/start_slave/libstart_slave.a \
		${LIB_DIR}/run_master/librun_master.a \
		${TOP_DIR}/libfmhub/libfmhub.a

install:

.include <bsd.prog.mk>

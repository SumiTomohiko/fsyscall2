
PROG=		java_tester
SRCS=		main.c
WITHOUT_MAN=	yes
TOP_DIR=	../..
CFLAGS+=	-I$(TOP_DIR)/include
LIB_DIR=	${TOP_DIR}/lib
LDADD+=		-lssl -lcrypto ${LIB_DIR}/close_or_die/libclose_or_die.a \
		${LIB_DIR}/fork_or_die/libfork_or_die.a \
		${LIB_DIR}/run_master/librun_master.a \
		${TOP_DIR}/libfmhub/libfmhub.a \

install:

.include <bsd.prog.mk>

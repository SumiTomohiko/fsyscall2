
PROG=		tester
SRCS=		main.c
WITHOUT_MAN=	yes
TOP_DIR=	../..
CFLAGS=		-I${TOP_DIR}/include
LIB_DIR=	${TOP_DIR}/lib
LDADD =		${LIB_DIR}/start_slave/libstart_slave.a \
		${LIB_DIR}/run_master/librun_master.a \
		${LIB_DIR}/close_or_die/libclose_or_die.a \
		${LIB_DIR}/fork_or_die/libfork_or_die.a \
		${LIB_DIR}/pipe_or_die/libpipe_or_die.a \
		${LIB_DIR}/die/libdie.a \
		${TOP_DIR}/libfmhub/libfmhub.a \
		${LIB_DIR}/geterrorname/libgeterrorname.a \
		${LIB_DIR}/payload/libpayload.a \
		${LIB_DIR}/atoi_or_die/libatoi_or_die.a \
		${LIB_DIR}/hub/libhub.a \
		${LIB_DIR}/close_or_die/libclose_or_die.a \
		${LIB_DIR}/fork_or_die/libfork_or_die.a ${LIB_DIR}/io/libio.a \
		${LIB_DIR}/io_or_die/libio_or_die.a ${LIB_DIR}/list/liblist.a \
		${LIB_DIR}/log/liblog.a \
		${LIB_DIR}/malloc_or_die/libmalloc_or_die.a \
		${LIB_DIR}/pipe_or_die/libpipe_or_die.a \
		${LIB_DIR}/encode/libencode.a ${LIB_DIR}/die/libdie.a \
		${LIB_DIR}/command/libcommand.a

install:

.include <bsd.prog.mk>

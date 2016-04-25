
PROG=		fmhub
SRCS=		main.c
TOP_DIR=	..
CFLAGS=		-I${TOP_DIR}/include
LIB_DIR=	${TOP_DIR}/lib
LDADD=		${LIB_DIR}/geterrorname/libgeterrorname.a \
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
WITHOUT_MAN=	yes

.include "${TOP_DIR}/Makefile.common"
.include <bsd.prog.mk>


PROG=		fmhub
SRCS=		main.c
TOP_DIR=	..
CFLAGS=		-I${TOP_DIR}/include
LIB_DIR=	${TOP_DIR}/lib
LDADD=		${LIB_DIR}/atoi_or_die/libatoi_or_die.a \
		${LIB_DIR}/close_or_die/libclose_or_die.a \
		${LIB_DIR}/fork_or_die/libfork_or_die.a ${LIB_DIR}/io/libio.a \
		${LIB_DIR}/list/liblist.a \
		${LIB_DIR}/malloc_or_die/libmalloc_or_die.a \
		${LIB_DIR}/pipe_or_die/libpipe_or_die.a \
		${LIB_DIR}/hub/libhub.a ${LIB_DIR}/encode/libencode.a
WITHOUT_MAN=	yes

.include <bsd.prog.mk>

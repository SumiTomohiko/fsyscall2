
LIB=		fmhub
SRCS=		main.c
TOP_DIR=	..
CFLAGS=		-I${TOP_DIR}/include
LIB_DIR=	${TOP_DIR}/lib
ARADD=		${LIB_DIR}/geterrorname/geterrorname.o \
		${LIB_DIR}/payload/fsyscall_payload.o \
		${LIB_DIR}/atoi_or_die/atoi_or_die.o ${LIB_DIR}/hub/hub.o \
		${LIB_DIR}/close_or_die/close_or_die.o \
		${LIB_DIR}/fork_or_die/fork_or_die.o ${LIB_DIR}/io/io.o \
		${LIB_DIR}/io_or_die/io_or_die.o ${LIB_DIR}/list/list.o \
		${LIB_DIR}/log/log.o ${LIB_DIR}/malloc_or_die/malloc_or_die.o \
		${LIB_DIR}/pipe_or_die/pipe_or_die.o \
		${LIB_DIR}/encode/fsyscall_encode.o ${LIB_DIR}/die/die.o \
		${LIB_DIR}/command/command.o
LIBDIR=		/lib

.include "${TOP_DIR}/Makefile.common"
.include <bsd.lib.mk>

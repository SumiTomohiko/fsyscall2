
PROG=		fslave
SRCS=		fslave_close.c dir_entries_cache.c stream.c main.c
TOP_DIR=	..
CFLAGS=		-I${TOP_DIR}/include
LIB_DIR=	${TOP_DIR}/lib
LDADD=		-lssl -lcrypto -lz ${LIB_DIR}/geterrorname/libgeterrorname.a \
		${LIB_DIR}/read_sockaddr/libread_sockaddr.a \
		${LIB_DIR}/payload/libpayload.a \
		${LIB_DIR}/fork_or_die/libfork_or_die.a \
		${LIB_DIR}/atoi_or_die/libatoi_or_die.a ${LIB_DIR}/io/libio.a \
		${LIB_DIR}/io_or_die/libio_or_die.a \
		${LIB_DIR}/malloc_or_die/libmalloc_or_die.a \
		${LIB_DIR}/encode/libencode.a ${LIB_DIR}/die/libdie.a \
		${LIB_DIR}/log/liblog.a ${LIB_DIR}/command/libcommand.a \
		${LIB_DIR}/select/libselect.a \
		${LIB_DIR}/close_or_die/libclose_or_die.a -lpthread
WITHOUT_MAN=	yes

.include "Makefile.makesyscalls"
.include "${TOP_DIR}/Makefile.common"
.include <bsd.prog.mk>

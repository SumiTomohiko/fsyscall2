
LIB=	libtiny_runtime.a
SRCS=	tiny_runtime.S memset.c isspace.c sigsetops.c stack_protector.c \
	strtol.c tr_run_chdir_x_test.c tr_run_client_server.c \
	tr_run_dup2_closed2x_test.c tr_run_dup2_master2x_test.c \
	tr_run_dup2_slave2x_test.c tr_print_str.c tr_print_num.c tr_wait_data.c
LST=	${.ALLSRC:M*.S:.S=.lst}
OBJS=	${SRCS:S/.c$/.o/:S/.S$/.o/}
CFLAGS=	-I ../include -include tiny_runtime.h -Werror -c

all: ${LIB}

${LIB}: ${OBJS}
	ar cr ${.TARGET} ${OBJS}

.S.o:
	nasm -f ${FORMAT} -o ${.TARGET} -l ${LST} ${NASMFLAGS} ${.ALLSRC:M*.S}

.c.o:
	clang -o ${.TARGET} ${CFLAGS} ${.ALLSRC}

clean:
	rm -f ${OBJS} ${LIB} *.lst

.include "../Makefile.amd64"

# vim: filetype=make

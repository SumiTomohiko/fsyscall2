
LIB=	libtiny_runtime.a
SRCS=	tiny_runtime.S isspace.c sigsetops.c strtol.c tr_run_chdir_x_test.c \
	tr_run_client_server.c tr_print_str.c tr_print_num.c
LST=	${.ALLSRC:M*.S:.S=.lst}
OBJS=	${SRCS:S/.c$/.o/:S/.S$/.o/}

all: ${LIB}

${LIB}: ${OBJS}
	ar cr ${.TARGET} ${OBJS}

.S.o:
	nasm -f ${FORMAT} -o ${.TARGET} -l ${LST} ${NASMFLAGS} ${.ALLSRC:M*.S}

.c.o:
	clang -o ${.TARGET} -I ../include -include tiny_runtime.h -c ${.ALLSRC}

clean:
	rm -f ${OBJS} ${LIB} *.lst

.include "../Makefile.amd64"

# vim: filetype=make

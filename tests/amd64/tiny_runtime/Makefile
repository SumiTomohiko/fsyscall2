
LIB=	libtiny_runtime.a
SRCS=	tiny_runtime.S sigsetops.c
LST=	${.ALLSRC:M*.S:.S=.lst}
OBJS=	${SRCS:S/.c$/.o/:S/.S$/.o/}

all: ${LIB}

${LIB}: ${OBJS}
	ar cr ${.TARGET} ${OBJS}

.S.o:
	nasm -f ${FORMAT} -o ${.TARGET} -l ${LST} ${NASMFLAGS} ${.ALLSRC:M*.S}

.c.o:
	clang -o ${.TARGET} -c ${.ALLSRC}

clean:
	rm -f ${OBJS} ${LIB} *.lst

.include "../Makefile.amd64"

# vim: filetype=make

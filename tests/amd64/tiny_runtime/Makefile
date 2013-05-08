
SRCS=	tiny_runtime.S
LST=	${.ALLSRC:M*.S:.S=.lst}
OBJS=	${SRCS:.S=.o}

all: ${OBJS}

${OBJS}: ${ADDITIONAL} Makefile

.S.o:
	nasm -f ${FORMAT} -o ${.TARGET} -l ${LST} ${NASMFLAGS} ${.ALLSRC:M*.S}

clean:
	rm -f ${OBJS} ${LIB} *.lst

.include "../Makefile.amd64"

# vim: filetype=make

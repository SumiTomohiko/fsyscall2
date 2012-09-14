
OBJS=		${PROG}.o
SRCS=		${PROG}.asm
ADDITIONAL+=	Makefile ../Makefile ../Makefile.asm

all: ${PROG}

${PROG}: ${OBJS}
	ld -o ${.TARGET} ${OBJS}

${OBJS}: ${SRCS} ${ADDITIONAL}
	nasm -f ${FORMAT} -o ${.TARGET} -l ${PROG}.lst ${SRCS}

clean:
	rm -f ${PROG} ${OBJS}

# vim: filetype=make

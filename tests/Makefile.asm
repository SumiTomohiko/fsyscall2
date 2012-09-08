
OBJS=		${PROG}.o
SRCS=		${PROG}.asm
ADDITIONAL=	../system.inc Makefile ../Makefile.asm

all: ${PROG}

${PROG}: ${OBJS}
	ld -o ${.TARGET} ${OBJS}

.include <sys.mk>

.if ${MACHINE_CPUARCH} == "amd64"
FORMAT=	elf64
.else
FORMAT=	elf
.endif

${OBJS}: ${SRCS} ${ADDITIONAL}
	nasm -f ${FORMAT} -o ${.TARGET} ${SRCS}

clean:
	rm -f ${PROG} ${OBJS}

# vim: filetype=make

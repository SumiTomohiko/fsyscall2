
OBJS=		${PROG}.o
SRCS=		${PROG}.asm
INCLUDED=	../system.inc

all: ${PROG}

${PROG}: ${OBJS}
	ld -o ${.TARGET} ${OBJS}

.include <sys.mk>

.if ${MACHINE_CPUARCH} == "amd64"
FORMAT=	elf64
.else
FORMAT=	elf
.endif

${OBJS}: ${SRCS} ${INCLUDED}
	nasm -f ${FORMAT} -o ${.TARGET} ${SRCS}

clean:
	rm -f ${PROG} ${OBJS}

# vim: filetype=make

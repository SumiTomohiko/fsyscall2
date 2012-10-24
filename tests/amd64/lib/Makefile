
LIB=	libtest.a
SRCS=	atoi.S exit.S print_num.S streq.S strlen.S
OBJS=	${SRCS:.S=.o}

all: ${LIB}

${LIB}: ${OBJS}
	${AR} cq ${.TARGET} ${OBJS}

${SRCS}: Makefile

.S.o:
	nasm -f elf64 -o ${.TARGET} -l ${.ALLSRC:.S=.lst} ${.ALLSRC}

clean:
	rm -f ${OBJS} ${LIB} *.lst

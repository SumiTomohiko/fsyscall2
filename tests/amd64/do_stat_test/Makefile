
LIB=		libdo_stat_test.a
ADDITIONAL=	name.inc print.inc
SRCS=		do_stat_test.S

GENERATOR=	print_stat_layout
GENERATOR_SRCS=	${GENERATOR}.c
CFLAGS+=	-g -Wall -Werror

${ADDITIONAL}: ${GENERATOR}
	./${GENERATOR}

${GENERATOR}: ${GENERATOR_SRCS} Makefile
	${CC} -o ${.TARGET} ${CFLAGS} ${GENERATOR_SRCS}

.include "../Makefile.lib"

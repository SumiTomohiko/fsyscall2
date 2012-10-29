
ADDITIONAL=	name.inc print.inc
LIB=		libprint_stat_member.a
SRCS=		print_stat_member.S

CFLAGS+=	-g -Wall -Werror
GENERATOR=	print_stat_layout
GENERATOR_SRCS=	${GENERATOR}.c

${ADDITIONAL}: ${GENERATOR}
	./${GENERATOR}

${GENERATOR}: ${GENERATOR_SRCS} Makefile
	${CC} -o ${.TARGET} ${CFLAGS} ${GENERATOR_SRCS}

.include "../Makefile.lib"

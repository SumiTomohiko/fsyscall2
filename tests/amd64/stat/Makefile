
PROG=		stat
ADDITIONAL=	name.inc print.inc

name.inc print.inc: print_stat_layout
	./print_stat_layout

print_stat_layout: print_stat_layout.c
	${CC} -o ${.TARGET} -g -Wall -Werror print_stat_layout.c

.include "../Makefile.asm"

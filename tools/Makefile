
CC=	clang
CFLAGS=	-Wall -Werror -Wextra -O3

all: format_logcat

format_logcat: format_logcat.o
	$(CC) -o format_logcat $(LDFLAGS) format_logcat.o

format_logcat.o: format_logcat.c Makefile

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -f format_logcat format_logcat.o

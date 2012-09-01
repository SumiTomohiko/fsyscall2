#if !defined(FSYSCALL_PRIVATE_H_INCLUDED)
#define FSYSCALL_PRIVATE_H_INCLUDED

#include <sys/types.h>

struct connection {
	int rfd;
	int wfd;
};

pid_t fork_or_die();
void close_or_die(int);
void pipe_or_die(int[2]);
void read_or_die(int, const void *, size_t);
void waitpid_or_die(pid_t, int *);
void write_or_die(int, const void *, size_t);
int atoi_or_die(const char *, const char *);

#define	R	0
#define	W	1

#define	ALLOC_FD(x, fd)	do {			\
	x = (char*)alloca(sizeof(char) * 16);	\
	sprintf(x, "%d", (fd));			\
} while (0)

#endif

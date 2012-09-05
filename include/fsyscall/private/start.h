#if !defined(FSYSCALL_PRIVATE_START_H_INCLUDED)
#define FSYSCALL_PRIVATE_START_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>

#define	ALLOC_FD(x, fd)	do {			\
	x = (char*)alloca(sizeof(char) * 16);	\
	sprintf(x, "%d", (fd));			\
} while (0)

#endif

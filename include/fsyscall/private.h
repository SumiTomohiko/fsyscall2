#if !defined(FSYSCALL_PRIVATE_H_INCLUDED)
#define FSYSCALL_PRIVATE_H_INCLUDED

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#define	TRACE_HEAD	getprogname(), getpid(), __FILE__, __LINE__
#define	TRACE(fmt, ...)	do {						\
	printf("%s[%d] %s:%u " fmt "\n", TRACE_HEAD, __VA_ARGS__);	\
	fflush(stdout);							\
	syslog(LOG_DEBUG, fmt, __VA_ARGS__);				\
} while (0)
#define	TRACE0(msg)	TRACE("%s", (msg))

#define	array_sizeof(a)	(sizeof(a) / sizeof(a[0]))

#endif

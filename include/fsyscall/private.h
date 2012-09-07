#if !defined(FSYSCALL_PRIVATE_H_INCLUDED)
#define FSYSCALL_PRIVATE_H_INCLUDED

#include <stdio.h>
#include <syslog.h>

#define	TRACE(fmt, ...)	do {						\
	printf("%s:%u " fmt "\n", __FILE__, __LINE__, __VA_ARGS__);	\
	fflush(stdout);							\
	syslog(LOG_DEBUG, fmt, __VA_ARGS__);				\
} while (0)
#define	TRACE0(msg)	TRACE("%s", (msg))

#define	array_sizeof(a)	(sizeof(a) / sizeof(a[0]))

#endif

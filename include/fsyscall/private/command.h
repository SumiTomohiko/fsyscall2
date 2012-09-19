#if !defined(FSYSCALL_PRIVATE_COMMAND_H_INCLUDED)
#define FSYSCALL_PRIVATE_COMMAND_H_INCLUDED

#include <sys/types.h>

typedef uint16_t command_t;

#define	CALL_EXIT	0
#define	CALL_WRITE	1

const char *get_command_name(command_t);

#endif

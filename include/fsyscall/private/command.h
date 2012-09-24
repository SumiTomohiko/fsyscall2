#if !defined(FSYSCALL_PRIVATE_COMMAND_H_INCLUDED)
#define FSYSCALL_PRIVATE_COMMAND_H_INCLUDED

#include <sys/types.h>

typedef uint32_t command_t;
typedef uint32_t payload_size_t;

#define	CALL_EXIT		0
#define	CALL_OPEN		1
#define	CALL_CLOSE		2
#define	CALL_WRITE		3
#define	RET_OF_CALL(cmd)	((cmd) << 16)
#define	RET_OPEN		RET_OF_CALL(CALL_OPEN)
#define	RET_CLOSE		RET_OF_CALL(CALL_CLOSE)
#define	RET_WRITE		RET_OF_CALL(CALL_WRITE)

const char *get_command_name(command_t);

#endif

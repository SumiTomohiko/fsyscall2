#if !defined(FSYSCALL_PRIVATE_COMMAND_H_INCLUDED)
#define FSYSCALL_PRIVATE_COMMAND_H_INCLUDED

#include <sys/types.h>

#include <fsyscall/private/command/code.h>

typedef uint32_t command_t;
typedef uint32_t payload_size_t;

const char *get_command_name(command_t);

#endif

#if !defined(FSYSCALL_PRIVATE_FORK_OR_DIE_H_INCLUDED)
#define FSYSCALL_PRIVATE_FORK_OR_DIE_H_INCLUDED

#include <sys/types.h>
#include <unistd.h>

pid_t fork_or_die();

#endif

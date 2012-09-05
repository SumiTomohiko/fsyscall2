#if !defined(FSYSCALL_PRIVATE_MALLOC_OR_DIE_H_INCLUDED)
#define FSYSCALL_PRIVATE_MALLOC_OR_DIE_H_INCLUDED

#include <sys/types.h>

void *malloc_or_die(size_t);

#endif

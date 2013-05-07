#if !defined(FSYSCALL_PRIVATE_SELECT_H_INCLUDED)
#define FSYSCALL_PRIVATE_SELECT_H_INCLUDED

#include <sys/select.h>
#include <sys/types.h>

int	fsyscall_count_fds(int, fd_set *);
int	fsyscall_encode_fds(int, struct fd_set *, char *, size_t);

#endif

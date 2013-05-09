#if !defined(FSYSCALL_PRIVATE_SELECT_H_INCLUDED)
#define FSYSCALL_PRIVATE_SELECT_H_INCLUDED

#include <sys/select.h>
#include <sys/types.h>

size_t	fsyscall_compute_fds_bufsize(int);
int	fsyscall_count_fds(int, fd_set *);
int	fsyscall_encode_fds(int, fd_set *, char *, size_t);

#endif

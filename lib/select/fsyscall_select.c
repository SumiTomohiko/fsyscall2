#include <sys/select.h>

#include <fsyscall/private/encode.h>
#include <fsyscall/private/select.h>

size_t
fsyscall_compute_fds_bufsize(int nfds)
{
	return (nfds * FSYSCALL_BUFSIZE_INT32);
}

int
fsyscall_count_fds(int nfds, fd_set *fds)
{
	int i, n;

	n = 0;
	for (i = 0; i < nfds; i++)
		if (FD_ISSET(i, fds))
			n++;

	return (n);
}

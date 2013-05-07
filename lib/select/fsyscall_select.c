#include <sys/select.h>

#include <fsyscall/private/select.h>

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

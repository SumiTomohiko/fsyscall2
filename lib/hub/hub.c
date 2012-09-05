#include <assert.h>
#include <stdlib.h>

#include <fsyscall/private/io.h>

void
transport_fds(int rfd, int wfd)
{
	int n;
	char *buf;

	n = read_int(rfd);
	assert(0 <= n);
	buf = (char *)alloca(sizeof(char) * n);
	read_or_die(rfd, buf, n);

	write_int(wfd, n);
	write_or_die(wfd, buf, n);
}

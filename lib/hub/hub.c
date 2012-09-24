#include <assert.h>
#include <stdlib.h>

#include <fsyscall/private/io.h>

void
transport_fds(int rfd, int wfd)
{
	int _, n;
	char *buf;

	n = read_int32(rfd, &_);
	assert(0 <= n);
	buf = (char *)alloca(sizeof(char) * n);
	read_or_die(rfd, buf, n);

	write_int32(wfd, n);
	write_or_die(wfd, buf, n);
}

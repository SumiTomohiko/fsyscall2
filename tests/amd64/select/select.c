#include <tiny_runtime.h>

/**
 * Test for select(2) with not-null timeout.
 */
int
main(int argc, char *argv[])
{
	fd_set writefds;
	struct timeval timeout;
	int fd = 1;

	FD_ZERO(&writefds);
	FD_SET(fd, &writefds);

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;

	return (select(fd + 1, NULL, &writefds, NULL, &timeout) == 1 ? 0 : 1);
}

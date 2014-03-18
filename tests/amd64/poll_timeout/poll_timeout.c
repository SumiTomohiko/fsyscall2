#include <tiny_runtime.h>

int
main(int argc, const char *argv[])
{
	struct pollfd fds[1];
	int fd, n;
	const char *path;

	if (argc != 2)
		return (1);
	path = argv[1];

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return (2);
	fds[0].fd = fd;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	n = poll(fds, sizeof(fds) / sizeof(fds[0]), 100);
	if (n != 0)
		return (3);

	return (0);
}

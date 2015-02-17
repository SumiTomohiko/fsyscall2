
int
main(int argc, const char *argv[])
{
	struct pollfd fds[1];
	int fd, n;
	const char *path;

	if (argc != 2)
		return (1);
	path = argv[1];

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return (2);
	fds[0].fd = fd;
	fds[0].events = POLLOUT;
	fds[0].revents = 0;
	n = poll(fds, sizeof(fds) / sizeof(fds[0]), 1000);
	if (n != 1)
		return (3);
	if ((fds[0].revents & POLLOUT) == 0)
		return (4);

	return (0);
}

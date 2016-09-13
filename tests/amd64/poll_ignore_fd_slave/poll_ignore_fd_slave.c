
int
main(int argc, const char *argv[])
{
	struct pollfd fds[2];
	int fd;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return (2);
	fds[0].fd = -1;
	fds[0].events = POLLSTANDARD;
	fds[0].revents = 0;
	fds[1].fd = fd;
	fds[1].events = POLLIN;
	fds[1].revents = 0;
	if (poll(fds, array_sizeof(fds), 0) != 1)
		return (3);
	if (fds[0].revents != 0)
		return (4);
	if (fds[1].revents != POLLIN)
		return (5);

	return (0);
}


int
main(int argc, const char *argv[])
{
	struct pollfd fds[3];
	int masterfd, slavefd;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	masterfd = open("/dev/null", O_RDONLY);
	if (masterfd == -1)
		return (2);
	slavefd = open(path, O_RDONLY);
	if (slavefd == -1)
		return (3);

	fds[0].fd = -1;
	fds[0].events = POLLSTANDARD;
	fds[0].revents = 0;
	fds[1].fd = masterfd;
	fds[1].events = POLLIN;
	fds[1].revents = 0;
	fds[2].fd = slavefd;
	fds[2].events = POLLIN;
	fds[2].revents = 0;
	if (poll(fds, array_sizeof(fds), 0) != 2)
		return (4);
	if (fds[0].revents != 0)
		return (5);
	if (fds[1].revents != POLLIN)
		return (6);
	if (fds[2].revents != POLLIN)
		return (7);

	return (0);
}

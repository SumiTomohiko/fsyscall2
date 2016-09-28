
int
main(int argc, const char *argv[])
{
	struct pollfd fds[1];
	int d;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	d = open(path, O_RDWR);
	if (d == -1)
		return (2);
	fds[0].fd = d;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	if (poll(fds, array_sizeof(fds), 0) != 1)
		return (3);
	if (fds[0].revents != POLLIN)
		return (4);

	return (0);
}

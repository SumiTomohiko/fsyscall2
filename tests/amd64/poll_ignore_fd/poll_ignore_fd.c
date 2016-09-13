
int
main(int argc, const char *argv[])
{
	struct pollfd fds[1];

	fds[0].fd = -1;
	fds[0].events = POLLSTANDARD;
	fds[0].revents = 0;
	if (poll(fds, array_sizeof(fds), 0) != 0)
		return (1);
	if (fds[0].revents != 0)
		return (2);

	return (0);
}

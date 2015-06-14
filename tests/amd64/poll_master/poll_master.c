
int
main(int argc, const char *argv[])
{
	struct pollfd pollfd;
	int error, fd;

	fd = open("/dev/null", O_WRONLY);
	if (fd == -1)
		return (1);

	pollfd.fd = fd;
	pollfd.events = POLLOUT;
	pollfd.revents = 0;
	if (poll(&pollfd, 1, 0) != 1)
		return (3);
	if ((pollfd.revents & POLLOUT) == 0)
		return (4);

	if (close(fd) == -1)
		return (2);

	return (0);
}

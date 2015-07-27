
#define	R	0
#define	W	1

int
main(int argc, const char *argv[])
{
	struct pollfd pollfd;
	int fds[2];
	char buf = 42, buf2;

	if (pipe(fds) == -1)
		return (1);
	if (write(fds[W], &buf, sizeof(buf)) != sizeof(buf))
		return (2);
	pollfd.fd = fds[R];
	pollfd.events = POLLIN;
	pollfd.revents = 0;
	if (poll(&pollfd, 1, 0) != 1)
		return (3);
	if (read(fds[R], &buf2, sizeof(buf2)) != sizeof(buf2))
		return (4);
	if (buf != buf2)
		return (5);

	return (0);
}

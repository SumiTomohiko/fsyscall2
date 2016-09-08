
static int
test(int fd)
{
	int n;

	n = fcntl(fd, F_GETFD);
	if (n == -1)
		return (1);

	return ((FD_CLOEXEC & n) != 0 ? 0 : 2);
}

int
main(int argc, const char *argv[])
{
	int fds[2], retval;

	if (pipe2(fds, O_CLOEXEC) == -1)
		return (1);
	retval = test(fds[0]);
	if (retval != 0)
		return (16 + retval);
	retval = test(fds[1]);
	if (retval != 0)
		return (32 + retval);

	return (0);
}

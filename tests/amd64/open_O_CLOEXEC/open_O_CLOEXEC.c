
int
main(int argc, const char *argv[])
{
	int fd, flags;

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return (1);
	flags = fcntl(fd, F_GETFD);
	if (flags == -1)
		return (2);
	if ((flags & FD_CLOEXEC) == 0)
		return (3);

	return (0);
}

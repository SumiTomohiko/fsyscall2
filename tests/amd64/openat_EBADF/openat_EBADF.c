
int
main(int argc, const char *argv[])
{
	int fd;

	fd = 42;
	close(fd);

	if (openat(fd, "foobarbaz", O_RDONLY) != -1)
		return (1);

	return (errno == EBADF ? 0 : 2);
}

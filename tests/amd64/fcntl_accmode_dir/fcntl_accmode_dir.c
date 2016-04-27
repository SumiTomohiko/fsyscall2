
int
main(int argc, const char *argv[])
{
	int fd, flags;

	fd = open("/", O_RDONLY);
	if (fd == -1)
		return (1);
	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		return (2);

	return ((O_ACCMODE & flags) == O_RDONLY ? 0 : 3);
}

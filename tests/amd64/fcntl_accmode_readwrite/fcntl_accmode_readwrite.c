
int
main(int argc, const char *argv[])
{
	int fd, flags;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	fd = open(path, O_RDWR);
	if (fd == -1)
		return (2);
	flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		return (3);

	return ((O_ACCMODE & flags) == O_RDWR ? 0 : 4);
}

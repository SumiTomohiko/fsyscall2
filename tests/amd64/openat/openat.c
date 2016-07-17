
int
main(int argc, const char *argv[])
{
	int dirfd, fd;
	const char *dir, *file;

	if (argc < 3)
		return (1);
	dir = argv[1];
	file = argv[2];

	dirfd = open(dir, O_RDONLY);
	if (dirfd == -1)
		return (2);
	fd = openat(dirfd, file, O_RDONLY);
	if (fd == -1)
		return (3);

	if (close(fd) == -1)
		return (4);
	if (close(dirfd) == -1)
		return (5);

	return (0);
}

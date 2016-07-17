
int
main(int argc, const char *argv[])
{
	int dirfd, fd;
	mode_t mode;
	char *endptr;
	const char *dir, *file;

	if (argc < 4)
		return (1);
	dir = argv[1];
	file = argv[2];
	mode = strtol(argv[3], &endptr, 8);
	if (endptr[0] != '\0')
		return (2);

	dirfd = open(dir, O_RDONLY);
	if (dirfd == -1)
		return (3);
	fd = openat(dirfd, file, O_WRONLY | O_CREAT, mode);
	if (fd == -1)
		return (4);

	if (close(fd) == -1)
		return (5);
	if (close(dirfd) == -1)
		return (6);

	return (0);
}


int
main(int argc, const char *argv[])
{
	int fd;
	const char *file;

	if (argc < 2)
		return (1);
	file = argv[1];

	fd = openat(-100, file, O_RDONLY);
	if (fd == -1)
		return (2);

	if (close(fd) == -1)
		return (3);

	return (0);
}

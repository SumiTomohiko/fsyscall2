
int
main(int argc, const char *argv[])
{
	int fd;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	fd = open(path, O_RDONLY | O_CREAT, 0644);
	if (fd == -1)
		return (2);
	if (fsync(fd) == -1)
		return (3);

	return (0);
}


int
main(int argc, const char *argv[])
{
	int fd;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	fd = open(path, O_RDONLY);
	if (fd != -1)
		return (2);
	if (errno != ENOENT)
		return (3);

	return (0);
}

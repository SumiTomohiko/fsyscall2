
int
main(int argc, const char *argv[])
{
	int fd;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	fd = open(path, O_RDONLY | O_DIRECTORY);
	if (fd != -1)
		return (0);

	return (errno == ENOTDIR ? 2 : 3);
}

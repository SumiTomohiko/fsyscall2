
int
main(int argc, const char *argv[])
{
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	if (access(path, 0400) != -1)
		return (2);
	if (errno != ENOENT)
		return (3);

	return (0);
}

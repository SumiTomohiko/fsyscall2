
int
main(int argc, const char *argv[])
{
	struct stat sb;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	if (stat(path, &sb) == 0)
		return (2);

	return (errno == ENOENT ? 0 : 3);
}

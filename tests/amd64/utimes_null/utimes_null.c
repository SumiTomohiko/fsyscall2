
int
main(int argc, const char *argv[])
{
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	return (utimes(path, NULL) == 0 ? 0 : 1);
}

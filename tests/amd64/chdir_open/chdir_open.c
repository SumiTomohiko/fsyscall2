
int
main(int argc, const char *argv[])
{
	const char *path;

	if (argc < 2)
		return (1);
	if (chdir("/") != 0)
		return (2);

	path = argv[1];
	if (*path != '/')
		return (3);
	if (open(&path[1], O_RDONLY) == -1)
		return (4);

	return (0);
}

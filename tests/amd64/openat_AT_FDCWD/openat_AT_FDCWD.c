
int
main(int argc, const char *argv[])
{
	const char *dir, *file;

	if (argc < 3)
		return (1);
	dir = argv[1];
	file = argv[2];

	if (chdir(dir) == -1)
		return (2);
	if (openat(AT_FDCWD, file, O_RDONLY) == -1)
		return (3);

	return (0);
}

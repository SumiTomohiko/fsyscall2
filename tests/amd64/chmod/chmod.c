
int
main(int argc, const char *argv[])
{
	struct stat sb;
	mode_t mode;
	char *endptr;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];
	mode = strtol(argv[2], &endptr, 8);
	if (*endptr != '\0')
		return (2);

	if (chmod(path, mode) == -1)
		return (3);

	return (0);
}

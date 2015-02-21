
int
main(int argc, const char *argv[])
{
	const char *path;

	if (argc < 2)
		return (64);
	path = argv[1];

	if (mkdir(path, 0777) == 0)
		return (0);
	if (errno == EACCES)
		return (1);

	return (2);
}

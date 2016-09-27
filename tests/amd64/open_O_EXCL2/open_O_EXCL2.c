
int
main(int argc, const char *argv[])
{
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	if (open(path, O_WRONLY | O_CREAT | O_EXCL, 0644) != -1)
		return (2);
	if (errno != EEXIST)
		return (3);

	return (0);
}

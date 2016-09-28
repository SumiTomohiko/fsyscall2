
int
main(int argc, const char *argv[])
{
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	if (open(path, O_WRONLY | O_CREAT, 0644) == -1)
		return (2);

	return (0);
}

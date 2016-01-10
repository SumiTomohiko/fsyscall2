
int
main(int argc, const char *argv[])
{
	struct timeval t[2];
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];
	bzero(t, sizeof(t));

	return (utimes(path, t) == 0 ? 0 : 1);
}

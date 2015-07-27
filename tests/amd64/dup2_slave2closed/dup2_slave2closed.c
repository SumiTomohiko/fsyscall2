
int
main(int argc, const char *argv[])
{
	struct stat sb;
	int fd = 42;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	/* ensure that the fd is closed */
	if (fstat(fd, &sb) != -1)
		return (2);
	if (errno != EBADF)
		return (3);

	return (tr_run_dup2_slave2x_test(fd, path));
}

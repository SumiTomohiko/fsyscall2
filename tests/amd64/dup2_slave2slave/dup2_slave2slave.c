
int
main(int argc, const char *argv[])
{
	int fd;
	const char *path1, *path2;

	if (argc < 3)
		return (1);
	path1 = argv[1];
	path2 = argv[2];

	fd = open(path1, O_WRONLY | O_CREAT, 0644);
	if (fd == -1)
		return (2);

	return (tr_run_dup2_slave2x_test(fd, path2));
}

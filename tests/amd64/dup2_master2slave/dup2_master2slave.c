
int
main(int argc, const char *argv[])
{
	int fd;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	fd = open(path, O_WRONLY | O_CREAT);
	if (fd == -1)
		return (2);

	return (tr_run_dup2_master2x_test(fd));
}


int
tr_run_dup2_closed2x_test(int to)
{
	struct stat sb;
	int fd = 42;

	if (fd == to)
		return (32);
	/* ensure that the fd is closed */
	if (fstat(fd, &sb) != -1)
		return (33);
	if (errno != EBADF)
		return (34);

	if (dup2(fd, to) != -1)
		return (35);
	if (errno != EBADF)
		return (36);

	return (0);
}

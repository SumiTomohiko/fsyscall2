
int
main(int argc, const char *argv[])
{
	struct stat sb;
	int fd = 26;

	/* ensure that the fd is closed */
	if (fstat(fd, &sb) != -1)
		return (1);
	if (errno != EBADF)
		return (2);

	return (tr_run_dup2_closed2x_test(fd));
}

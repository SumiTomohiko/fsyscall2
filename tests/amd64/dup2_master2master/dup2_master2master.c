
int
main(int argc, const char *argv[])
{
	int fd;

	fd = open("/dev/null", O_RDONLY);
	if (fd == -1)
		return (1);

	return (tr_run_dup2_master2x_test(fd));
}

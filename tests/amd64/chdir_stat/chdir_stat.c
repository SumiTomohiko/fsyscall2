
static int
callback(const char *path)
{
	struct stat sb;

	return (stat(path, &sb) == 0 ? 0 : 1);
}

int
main(int argc, const char *argv[])
{

	return (tr_run_chdir_x_test(argc, argv, callback));
}

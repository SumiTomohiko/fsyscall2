
static int
callback(const char *path)
{

	return (access(path, F_OK) == 0 ? 0 : 1);
}

int
main(int argc, const char *argv[])
{

	return (tr_run_chdir_x_test(argc, argv, callback));
}

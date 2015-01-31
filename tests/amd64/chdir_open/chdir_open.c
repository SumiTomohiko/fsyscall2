
static int
callback(const char *path)
{

	return (open(path, O_RDONLY) != -1 ? 0 : 1);
}

int
main(int argc, const char *argv[])
{

	return (tr_run_chdir_x_test(argc, argv, callback));
}

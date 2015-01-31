
int
tr_run_chdir_x_test(int argc, const char *argv[], tr_chdir_callback callback)
{
	const char *path;

	if (argc < 2)
		return (192);
	if (chdir("/") != 0)
		return (193);

	path = argv[1];
	if (*path != '/')
		return (194);

	return (callback(&path[1]));
}

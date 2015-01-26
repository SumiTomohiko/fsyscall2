
int
main(int argc, const char *argv[])
{

	if (argc < 2)
		return (1);
	if (chdir(argv[1]) != -1)
		return (2);

	return (0);
}

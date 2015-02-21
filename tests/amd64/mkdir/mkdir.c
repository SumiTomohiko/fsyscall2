
int
main(int argc, const char *argv[])
{

	if (argc < 2)
		return (64);

	return (mkdir(argv[1], 0777) == 0 ? 0 : 1);
}

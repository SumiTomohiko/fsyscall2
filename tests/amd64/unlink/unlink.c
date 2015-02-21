
int
main(int argc, const char *argv[])
{

	if (argc < 2)
		return (64);

	return (unlink(argv[1]) == 0 ? 0 : 1);
}

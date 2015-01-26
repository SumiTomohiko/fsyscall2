
int
main(int argc, const char *argv[])
{

	if (argc < 2)
		return (1);
	if (chdir("/") != 0)
		return (2);
	if (open(&argv[1][1], O_RDONLY) == -1)
		return (3);

	return (0);
}

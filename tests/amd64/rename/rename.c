
int
main(int argc, const char *argv[])
{
	const char *from, *to;

	if (argc < 3)
		return (1);
	from = argv[1];
	to = argv[2];

	if (rename(from, to) == -1)
		return (2);

	return (0);
}

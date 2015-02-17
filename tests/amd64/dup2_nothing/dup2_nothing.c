
int
main(int argc, const char *argv[])
{
	int d = 1;

	return (dup2(d, d) != -1 ? 0 : 1);
}

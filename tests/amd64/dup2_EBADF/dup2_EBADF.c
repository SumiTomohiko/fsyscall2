
int
main(int argc, const char *argv[])
{

	if (dup2(42, 26) != -1)
		return (1);
	if (errno != EBADF)
		return (2);

	return (0);
}

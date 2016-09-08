
int
main(int argc, const char *argv[])
{
	int fds[2];

	if (pipe2(fds, 0) == -1)
		return (1);

	return (0);
}

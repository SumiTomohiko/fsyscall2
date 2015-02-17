
int
main(int argc, const char *argv[])
{
	int newd = 42;
	const char *msg = "OK";

	if (dup2(1, newd) == -1)
		return (1);
	write(newd, msg, strlen(msg));

	return (0);
}

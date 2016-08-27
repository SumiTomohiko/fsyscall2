
int
main(int argc, const char *argv[])
{

	if (shutdown(0, SHUT_RD) != -1)
		return (1);
	if (errno != ENOTSOCK)
		return (2);

	return (0);
}

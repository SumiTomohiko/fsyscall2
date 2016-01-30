
int
main(int argc, const char *argv[])
{

	if (wait4(1, NULL, 0, NULL) != -1)
		return (1);
	if (errno != ECHILD)
		return (2);

	return (0);
}

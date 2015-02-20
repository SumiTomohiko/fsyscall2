
int
main(int argc, const char *argv[])
{

	if (chmod("/", 0777) != -1)
		return (1);
	if (errno != EPERM)
		return (2);

	return (0);
}

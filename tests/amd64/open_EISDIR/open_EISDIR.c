
int
main(int argc, const char *argv[])
{
	int fd;

	fd = open("/tmp", O_WRONLY);
	if (fd != -1)
		return (1);
	if (errno != EISDIR)
		return (2);

	return (0);
}

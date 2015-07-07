
int
main(int argc, const char *argv[])
{
	int error, fd;

	fd = open("/etc/pwd.db", O_RDONLY, 0644);
	if (fd == -1)
		return (1);
	error = close(fd);
	if (error == -1)
		return (2);

	return (0);
}


int
main(int argc, const char *argv[])
{
	int fd = 42;

	close(fd);

	if (shutdown(fd, SHUT_RD) != -1)
		return (1);
	if (errno != EBADF)
		return (2);

	return (0);
}

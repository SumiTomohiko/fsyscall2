
/**
 * Test for select(2) with null timeout.
 */
int
main(int argc, char *argv[])
{
	fd_set writefds;
	int fd = 1;

	FD_ZERO(&writefds);
	FD_SET(fd, &writefds);

	return (select(fd + 1, NULL, &writefds, NULL, NULL) == 1 ? 0 : 1);
}

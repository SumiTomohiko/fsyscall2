
int
main(int argc, const char *argv[])
{
	struct pollfd fds[1];
	int sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	fds[0].fd = sock;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	if (poll(fds, array_sizeof(fds), 0) != 0)
		return (2);

	return (0);
}

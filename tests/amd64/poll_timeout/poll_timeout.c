
static int
connect_callback(int s)
{
	struct pollfd fds[1];
	int n;

	fds[0].fd = s;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	n = poll(fds, sizeof(fds) / sizeof(fds[0]), 100 /* msec */);
	if (n != 0)
		return (1);

	return (0);
}

int
main(int argc, const char *argv[])
{
	int error;

	error = tr_run_client_server(argv[1], NULL, connect_callback);

	return (error);
}

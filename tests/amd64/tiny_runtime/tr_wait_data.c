
int
tr_wait_data(int fd)
{
	struct pollfd pollfd;

	pollfd.fd = fd;
	pollfd.events = POLLIN;
	pollfd.revents = 0;

	if (poll(&pollfd, 1, 8000 /* msec */) != 1)
		return (-1);

	return ((pollfd.revents & POLLIN) != 0 ? 0 : -1);
}

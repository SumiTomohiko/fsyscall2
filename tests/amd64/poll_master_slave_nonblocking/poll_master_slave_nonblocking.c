
int
main(int argc, const char *argv[])
{
	struct pollfd fds[2];
	int error, mfd, nfds, sfd;
	const char *spath;

	if (argc != 2)
		return (1);
	spath = argv[1];

	mfd = open("/dev/null", O_WRONLY);
	if (mfd == -1)
		return (2);
	sfd = open(spath, O_CREAT | O_WRONLY, 0644);
	if (sfd == -1)
		return (3);

	fds[0].fd = mfd;
	fds[1].fd = sfd;
	fds[0].events = fds[1].events = POLLOUT;
	fds[0].revents = fds[1].revents = 0;
	nfds = array_sizeof(fds);
	if (poll(fds, nfds, 0) != nfds)
		return (4);
	if ((fds[0].revents & POLLOUT) == 0)
		return (5);
	if ((fds[1].revents & POLLOUT) == 0)
		return (6);

	if (close(mfd) == -1)
		return (7);
	if (close(sfd) == -1)
		return (8);

	return (0);
}

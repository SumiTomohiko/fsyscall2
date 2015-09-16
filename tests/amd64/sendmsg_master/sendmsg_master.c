
int
main(int argc, const char *argv[])
{
	struct msghdr msg;
	struct iovec iov;
	int rfd, sv[2], wfd;
	char buf[1], c;

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sv) == -1)
		return (1);
	rfd = sv[0];
	wfd = sv[1];

	c = '*';
	iov.iov_base = &c;
	iov.iov_len = sizeof(c);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	if (sendmsg(wfd, &msg, 0) != sizeof(c))
		return (2);

	if (read(rfd, buf, sizeof(buf)) != sizeof(buf))
		return (3);
	if (buf[0] != c)
		return (4);

	if (close(rfd) == -1)
		return (5);
	if (close(wfd) == -1)
		return (6);

	return (0);
}

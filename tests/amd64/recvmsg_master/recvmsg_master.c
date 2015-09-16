
int
main(int argc, const char *argv[])
{
	struct msghdr msg;
	struct iovec iov;
	int rfd, sv[2], wfd;
	char buf[1], datum;

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, sv) == -1)
		return (1);
	rfd = sv[0];
	wfd = sv[1];

	datum = '*';
	if (write(wfd, &datum, sizeof(datum)) != sizeof(datum))
		return (2);

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	if (recvmsg(rfd, &msg, 0) != sizeof(datum))
		return (3);
	if (datum != buf[0])
		return (4);

	if (close(rfd) == -1)
		return (5);
	if (close(wfd) == -1)
		return (6);

	return (0);
}

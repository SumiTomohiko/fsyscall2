
int
main(int argc, const char *argv[])
{
	struct msghdr msg;
	struct iovec iov;
	int sock;
	char c;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	c = 42;
	iov.iov_base = &c;
	iov.iov_len = sizeof(c);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	if (sendmsg(sock, &msg, 0) != -1)
		return (2);
	if (errno != ENOTCONN)
		return (3);

	return (0);
}

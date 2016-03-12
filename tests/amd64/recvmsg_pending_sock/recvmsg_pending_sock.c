
int
main(int argc, const char *argv[])
{
	struct msghdr msg;
	struct iovec iov;
	int sock;
	char buf[8192], control[8192], name[8192];

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_name = name;
	msg.msg_namelen = sizeof(name);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	msg.msg_flags = 0;
	if (recvmsg(sock, &msg, 0) != -1)
		return (2);
	if (errno != ENOTCONN)
		return (3);

	return (0);
}

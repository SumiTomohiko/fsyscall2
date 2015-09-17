
int
main(int argc, const char *argv[])
{
	struct msghdr msg;
	struct iovec iov;
	int fd;
	const char *path;
	char datum;

	if (argc < 2)
		return (1);
	path = argv[1];

	fd = open(path, O_RDONLY, 0644);
	if (fd == -1)
		return (2);
	datum = '*';
	iov.iov_base = &datum;
	iov.iov_len = sizeof(datum);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen =  0;
	msg.msg_flags = 0;
	if (recvmsg(fd, &msg, 0) != -1)
		return (3);
	if (errno != ENOTSOCK)
		return (4);

	return (0);
}

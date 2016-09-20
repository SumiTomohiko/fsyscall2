
int
main(int argc, const char *argv[])
{
	int flags, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock == -1)
		return (1);
	flags = fcntl(sock, F_GETFD);
	if (flags == -1)
		return (2);
	if ((FD_CLOEXEC & flags) == 0)
		return (3);

	return (0);
}


int
main(int argc, const char *argv[])
{
	int flags, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	flags = fcntl(sock, F_GETFL);
	if (flags == -1)
		return (2);

	return ((O_ACCMODE & flags) == O_RDWR ? 0 : 3);
}

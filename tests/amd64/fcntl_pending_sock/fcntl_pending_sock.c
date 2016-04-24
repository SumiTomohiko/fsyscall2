
int
main(int argc, const char *argv[])
{
	int flags, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1)
		return (2);
	flags = O_NONBLOCK | O_APPEND | O_DIRECT | O_ASYNC;
	if ((fcntl(sock, F_GETFL) & flags) != O_NONBLOCK)
		return (3);

	return (0);
}

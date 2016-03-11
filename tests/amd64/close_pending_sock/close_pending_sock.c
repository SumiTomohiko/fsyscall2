
int
main(int argc, const char *argv[])
{
	int sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	if (close(sock) == -1)
		return (2);

	return (0);
}

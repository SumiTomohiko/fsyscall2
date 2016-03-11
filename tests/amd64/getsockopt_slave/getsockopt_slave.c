
int
main(int argc, const char *argv[])
{
	struct sockaddr_un addr;
	socklen_t optlen;
	int level, name, optval, optval2, sock;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (2);
	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, path);
	addr.sun_len = SUN_LEN(&addr);
	if (bind(sock, (struct sockaddr *)&addr, addr.sun_len) == -1)
		return (3);
	level = SOL_SOCKET;
	name = SO_REUSEADDR;
	optval = 1;
	if (setsockopt(sock, level, name, &optval, sizeof(optval)) == -1)
		return (4);
	optlen = sizeof(optval2);
	if (getsockopt(sock, level, name, &optval2, &optlen) == -1)
		return (5);
	if (optlen != sizeof(int))
		return (6);
	if (optval2 == 0)
		return (7);
	if (close(sock) == -1)
		return (8);

	return (0);
}

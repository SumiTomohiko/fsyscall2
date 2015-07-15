
static struct sockaddr_storage addr;

int
main(int argc, const char *argv[])
{
	struct sockaddr_un *paddr;
	struct stat sb;
	int sock;
	const char *path;

	if (argc < 2)
		return (32);
	path = argv[1];

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (2);
	paddr = (struct sockaddr_un *)&addr;
	paddr->sun_family = AF_UNIX;
	strcpy(paddr->sun_path, path);
	paddr->sun_len = SUN_LEN(paddr);
	if (bind(sock, (struct sockaddr *)paddr, paddr->sun_len) == -1)
		return (3);
	if (fstat(sock, &sb) == -1)
		return (4);
	if (close(sock) == -1)
		return (5);
	if (unlink(paddr->sun_path) == -1)
		return (6);

	return (0);
}

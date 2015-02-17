
static struct sockaddr_storage addr;

int
main(int argc, const char *argv[])
{
	int error, sock;
	struct sockaddr_un *paddr;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);

	paddr = (struct sockaddr_un *)&addr;
	paddr->sun_family = AF_LOCAL;
	strcpy(paddr->sun_path, argv[1]);
	paddr->sun_len = SUN_LEN(paddr);
	error = bind(sock, (struct sockaddr *)paddr, paddr->sun_len);
	if (error != 0)
		return (2);

	return (0);
}

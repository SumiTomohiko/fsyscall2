
static struct sockaddr_storage addr;

int
main(int argc, const char *argv[])
{
	struct sockaddr_un *paddr;
	int retval, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	paddr = (struct sockaddr_un *)&addr;
	paddr->sun_family = AF_LOCAL;
	strcpy(paddr->sun_path, argv[1]);
	paddr->sun_len = SUN_LEN(paddr);
	retval = bind(sock, (struct sockaddr *)paddr, paddr->sun_len);
	if (retval == -1)
		return (2);
	if (listen(sock, 0) == -1)
		return (3);

	return (0);
}

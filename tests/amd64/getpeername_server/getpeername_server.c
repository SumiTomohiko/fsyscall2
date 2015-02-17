
static struct sockaddr_storage storage;

static int
callback(int s, struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_un *paddr;
	socklen_t namelen;
	int error;

	paddr = (struct sockaddr_un *)&storage;
	namelen = sizeof(storage);
	error = getpeername(s, (struct sockaddr *)paddr, &namelen);
	if (error != 0)
		return (error);
	tr_print_num(strlen(paddr->sun_path));

	return (0);
}

int
main(int argc, const char *argv[])
{
	int error;

	error = tr_run_client_server(argv[1], callback, NULL);

	return (error);
}

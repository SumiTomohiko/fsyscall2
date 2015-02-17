
static struct sockaddr_storage addr;

static int
callback(int s)
{
	struct sockaddr *paddr;
	socklen_t namelen;
	int error;

	paddr = (struct sockaddr *)&addr;
	namelen = sizeof(addr);
	error = getpeername(s, paddr, &namelen);
	if (error != 0)
		return (error);
	print_num(paddr->sa_family);

	return (0);
}

int
main(int argc, const char *argv[])
{
	int error;

	error = tr_run_client_server(argv[1], NULL, callback);

	return (error);
}


static struct sockaddr_storage storage;

static int
callback(int s, struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_un *name;
	socklen_t namelen;
	int error;

	name = (struct sockaddr_un *)&storage;
	namelen = sizeof(storage);
	error = getsockname(s, (struct sockaddr *)name, &namelen);
	if (error != 0)
		return (error);
	tr_print_str(name->sun_path);

	return (0);
}

int
main(int argc, const char *argv[])
{
	int error;

	error = tr_run_client_server(argv[1], callback, NULL);

	return (error);
}

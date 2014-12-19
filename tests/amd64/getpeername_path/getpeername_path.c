#include <tiny_runtime.h>

static struct sockaddr_storage addr;

static int
callback(int s)
{
	struct sockaddr_un *paddr;
	socklen_t namelen;
	int error;

	paddr = (struct sockaddr_un *)&addr;
	namelen = sizeof(addr);
	error = getpeername(s, (struct sockaddr *)paddr, &namelen);
	if (error != 0)
		return (error);
	tr_print_str(paddr->sun_path);

	return (0);
}

int
main(int argc, const char *argv[])
{
	int error;

	error = tr_run_client_server(argv[1], NULL, callback);

	return (error);
}

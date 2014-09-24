#include <tiny_runtime.h>

struct sockaddr_storage addr, addr2;

int
main(int argc, const char *argv[])
{
	struct sockaddr_un *paddr, *paddr2;
	size_t len;
	socklen_t namelen;
	int error, sock;

	sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	paddr = (struct sockaddr_un *)&addr;
	paddr->sun_family = PF_LOCAL;
	strcpy(paddr->sun_path, argv[1]);
	paddr->sun_len = SUN_LEN(paddr);
	error = connect(sock, (struct sockaddr *)&addr, paddr->sun_len);
	if (error != 0)
		return (1);

	paddr2 = (struct sockaddr_un *)&addr2;
	namelen = sizeof(addr2);
	error = getpeername(sock, (struct sockaddr *)paddr2, &namelen);
	if (error != 0)
		return (2);
	len = strlen(paddr2->sun_path);
	write(1, paddr2->sun_path, len);

	close(sock);

	return (0);
}

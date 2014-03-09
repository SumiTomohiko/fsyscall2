#include <tiny_runtime.h>

/*
 * If the following sockaddr is placed in the main function, clang cannot link
 * this file because of lack of __stack_chk_guard. This must be in the main
 * function.
 */
static struct sockaddr_storage sockaddr;

int
main(int argc, char *argv[])
{
	struct sockaddr_un *paddr;
	int sock;
	socklen_t len;
	char *sockfile;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	paddr = (struct sockaddr_un *)&sockaddr;
	sockfile = argv[1];
	paddr->sun_len = len = sizeof(paddr->sun_len) + sizeof(paddr->sun_family) + strlen(sockfile) + 1;
	paddr->sun_family = AF_UNIX;
	strcpy(paddr->sun_path, sockfile);
	if (connect(sock, (struct sockaddr *)paddr, len) != 0)
		return (2);

	return (0);
}

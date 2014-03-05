#include <tiny_runtime.h>

int
main(int argc, const char *argv[])
{
	int sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);

	return sock != -1 ? 0 : 1;
}

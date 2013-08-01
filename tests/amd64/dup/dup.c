#include <tiny_runtime.h>

int
main(int argc, const char *argv[])
{
	int fd = dup(1);
	const char *msg = argv[1];

	write(1, msg, strlen(msg));

	return (0);
}

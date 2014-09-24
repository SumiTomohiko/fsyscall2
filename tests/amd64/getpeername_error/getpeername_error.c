#include <tiny_runtime.h>

static struct sockaddr_storage name;

int
main(int argc, const char *argv[])
{
	socklen_t namelen;
	int error;

	namelen = sizeof(name);
	error = getpeername(1024, (struct sockaddr *)&name, &namelen);
	if (error == 0)
		return (1);

	return (0);
}

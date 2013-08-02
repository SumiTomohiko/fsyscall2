#include <tiny_runtime.h>

static struct statfs buf;

int
main(int argc, const char *argv[])
{
	int fd;

	fd = open("/lib/libc.so.7", O_RDONLY);
	return (fstatfs(fd, &buf));
}

#include <tiny_runtime.h>

#define	BUFSIZE	(1024 * 1024)

int
main(int argc, const char *argv[])
{
	long pos;
	int fd;
	char buf[BUFSIZE];

	fd = open("/usr/lib/", O_RDONLY);
	return (0 < getdirentries(fd, buf, BUFSIZE, &pos) ? 0 : 1);
}

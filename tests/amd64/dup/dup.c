#include <tiny_runtime.h>

static char buf[8192];

static int
atoi(const char *nptr)
{
	int n = 0;
	const char *p;

	for (p = nptr; *p != '\0'; p++)
		n = 10 * n + (*p - '0');

	return (n);
}

int
main(int argc, const char *argv[])
{
	size_t len;
	int fd, fd2;

	fd = open(argv[1], O_RDONLY);
	fd2 = dup(fd);
	len = atoi(argv[2]);
	read(fd2, buf, len);
	write(1, buf, len);

	return (0);
}

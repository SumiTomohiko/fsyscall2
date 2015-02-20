
static char buf[8192];

int
main(int argc, const char *argv[])
{
	size_t len;
	int fd, fd2;

	fd = open(argv[1], O_RDONLY);
	fd2 = dup(fd);
	len = strtol(argv[2], NULL, 10);
	read(fd2, buf, len);
	write(1, buf, len);

	return (0);
}

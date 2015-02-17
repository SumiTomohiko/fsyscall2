
#define	BUFSIZE	(1024 * 1024)

static char buf[BUFSIZE];

int
main(int argc, const char *argv[])
{
	long pos;
	int fd;

	fd = open("/usr/lib/", O_RDONLY);
	return (0 < getdirentries(fd, buf, BUFSIZE, &pos) ? 0 : 1);
}


#define	IN_MAX	8

int
main(int argc, const char *argv[])
{
	struct iovec iov[IN_MAX];
	ssize_t len, size;
	int fd, i, nin;
	const char *in[IN_MAX], *out;
	char buf[IN_MAX][1 * 1024 * 1024];

	if (argc < 3)
		return (1);
	out = argv[1];
	nin = MIN(argc - 2, array_sizeof(in));
	for (i = 0; i < nin; i++)
		in[i] = argv[i + 2];

	size = 0;
	for (i = 0; i < nin; i++) {
		fd = open(in[i], O_RDONLY);
		if (fd == -1)
			return (2);

		len = read(fd, buf[i], sizeof(buf[i]));
		if (len == -1)
			return (3);
		iov[i].iov_base = buf[i];
		iov[i].iov_len = len;
		size += len;

		if (close(fd) == -1)
			return (4);
	}

	fd = open(out, O_WRONLY | O_CREAT, 0644);
	if (fd == -1)
		return (5);
	if (writev(fd, iov, nin) != size)
		return (6);
	if (close(fd) == -1)
		return (7);

	return (0);
}

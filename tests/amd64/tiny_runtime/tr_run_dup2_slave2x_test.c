
int
tr_run_dup2_slave2x_test(int to, const char *path)
{
	struct stat sb;
	struct pollfd pollfd;
	int fd, fd2;
	char buf = 42, buf2;

	fd = open(path, O_WRONLY | O_CREAT, 0644);
	if (fd == -1)
		return (32);
	/* ensure that the file is newly created */
	if (fstat(fd, &sb) == -1)
		return (33);
	if (sb.st_size != 0)
		return (34);
	if (fd == to)
		return (35);
	if (dup2(fd, to) == -1)
		return (36);
	if (write(to, &buf, sizeof(buf)) == -1)
		return (37);
	if (close(to) == -1)
		return (38);
	if (close(fd) == -1)
		return (39);

	fd2 = open(path, O_RDONLY);
	if (fd2 == -1)
		return (40);
	pollfd.fd = fd2;
	pollfd.events = POLLIN;
	pollfd.revents = 0;
	if (poll(&pollfd, 1, 0) != 1)
		return (41);
	if (read(fd2, &buf2, sizeof(buf2)) == -1)
		return (42);
	if (buf2 != buf)
		return (43);
	if (close(fd2) == -1)
		return (44);

	return (0);
}

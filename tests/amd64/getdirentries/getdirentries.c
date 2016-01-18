
int
main(int argc, const char *argv[])
{
	const struct dirent *dir;
	long pos;
	int fd, nbytes;
	const char *name, *p, *path, *pend;
	char buf[8192];

	if (argc < 2)
		return (1);
	path = argv[1];
	fd = open(path, O_RDONLY | O_DIRECTORY);
	if (fd == -1)
		return (2);

	while (0 < (nbytes = getdirentries(fd, buf, sizeof(buf), &pos))) {
		p = buf;
		pend = buf + nbytes;
		while (p < pend) {
			dir = (struct dirent *)p;
			name = dir->d_name;
			if (strcmp(name, ".") == 0)
				;
			else if (strcmp(name, "..") == 0)
				;
			else
				puts(name);

			p += dir->d_reclen;
		}
	}
	if (nbytes == -1)
		return (3);

	return (0);
}

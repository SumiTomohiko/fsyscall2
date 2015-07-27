
#define	R	0
#define	W	1

int
tr_run_dup2_master2x_test(int to)
{
	int fds[2];
	char buf = 42, buf2;

	if (pipe(fds) == -1)
		return (32);
	if (fds[W] == to)
		return (33);
	if (dup2(fds[W], to) == -1)
		return (34);
	if (write(to, &buf, sizeof(buf)) == -1)
		return (35);
	if (close(to) == -1)
		return (36);
	if (read(fds[R], &buf2, sizeof(buf2)) == -1)
		return (37);
	if (buf2 != buf)
		return (38);
	if (close(fds[R]) == -1)
		return (39);
	if (close(fds[W]) == -1)
		return (40);

	return (0);
}

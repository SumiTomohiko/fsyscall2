
static int
waitee_main(int fd)
{
	pid_t pid;

	pid = getpid();
	if (write(fd, &pid, sizeof(pid)) != sizeof(pid))
		return (1);
	if (close(fd) == -1)
		return (2);

	for (;;)
		;

	/* NOTREACHED */
	return (3);
}

#define	R	0
#define	W	1

static int
waiter_main(int fds[2])
{
	pid_t pid;
	int wfd;

	if (close(fds[R]) == -1)
		return (1);

	wfd = fds[W];
	pid = fork();
	switch (pid) {
	case -1:
		return (2);
	case 0:
		return (waitee_main(wfd));
	default:
		break;
	}

	if (close(wfd) == -1)
		return (3);
	wait4(pid, NULL, 0, NULL);
	/* NOTREACHED */

	return (4);
}

int
main(int argc, const char *argv[])
{
	struct timespec timeout;
	pid_t cpid, pid;
	int fds[2], rfd, sig, status;

	if (pipe(fds) == -1)
		return (1);

	pid = fork();
	switch (pid) {
	case -1:
		return (2);
	case 0:
		return (waiter_main(fds));
	default:
		break;
	}

	if (close(fds[W]) == -1)
		return (3);
	rfd = fds[R];
	if (read(rfd, &cpid, sizeof(cpid)) != sizeof(cpid))
		return (4);
	if (close(rfd) == -1)
		return (5);
	timeout.tv_sec = 1;
	timeout.tv_nsec = 0;
	if (nanosleep(&timeout, NULL) == -1)
		return (6);

	sig = SIGKILL;
	if (kill(pid, sig) == -1)
		return (7);
	if (wait4(pid, &status, 0, NULL) == -1)
		return (8);
	if (!WIFSIGNALED(status))
		return (9);
	if (WTERMSIG(status) != sig)
		return (10);

	if (kill(cpid, SIGKILL) == -1)
		return (11);

	return (0);
}

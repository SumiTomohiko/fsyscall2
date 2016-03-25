
#define	R	0

static int
child_main()
{
	struct pollfd fd;
	int fds[2];

	if (pipe(fds) == -1)
		return (1);
	fd.fd = fds[R];
	fd.events = POLLIN;
	fd.revents = 0;
	poll(&fd, 1, -1);
	/* NOTREACHED */

	return (2);
}

static int
parent_main(pid_t pid)
{
	struct timespec t;
	int sig, status;

	t.tv_sec = 1;
	t.tv_nsec = 0;
	if (nanosleep(&t, NULL) == -1)
		return (1);
	sig = SIGKILL;
	if (kill(pid, sig) == -1)
		return (2);
	if (wait4(pid, &status, 0, NULL) == -1)
		return (3);
	if (!WIFSIGNALED(status))
		return (4);
	if (WTERMSIG(status) != sig)
		return (5);

	return (0);
}

int
main(int argc, const char *argv[])
{
	pid_t pid;

	pid = fork();
	switch (pid) {
	case -1:
		return (1);
	case 0:
		return (child_main());
	default:
		return (parent_main(pid));
	}
}


#define	SIG	SIGUSR1
#define	TIME	10	/* sec */

static int
child_main(const char *path, sigset_t *set)
{
	struct timespec t;
	int fd, sig;
	char c;

	if (sigwait(set, &sig) != 0)
		return (1);
	if (sig != SIG)
		return (2);
	t.tv_sec = TIME / 2;
	t.tv_nsec = 0;
	if (nanosleep(&t, NULL) == -1)
		return (3);

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return (4);
	c = 'x';
	if (write(fd, &c, sizeof(c)) != sizeof(c))
		return (5);
	if (close(fd) == -1)
		return (6);

	return (0);
}

#define	R	0
#define	W	1

int
main(int argc, const char *argv[])
{
	struct pollfd fds[2];
	pid_t pid;
	sigset_t oset, set;
	int child_status, fildes[2], mfd, sfd, status;
	const char *spath;

	if (argc != 2)
		return (1);
	spath = argv[1];

	if (sigemptyset(&set) == -1)
		return (2);
	if (sigaddset(&set, SIG) == -1)
		return (3);
	if (sigprocmask(SIG_BLOCK, &set, &oset) == -1)
		return (4);

	pid = fork();
	if (pid == -1)
		return (5);
	if (pid == 0)
		return (child_main(spath, &set));

	if (sigprocmask(SIG_SETMASK, &oset, NULL) == -1)
		return (6);

	if (pipe(fildes) == -1)
		return (7);
	mfd = fildes[R];
	sfd = open(spath, O_CREAT | O_RDONLY, 0644);
	if (sfd == -1)
		return (8);
	if (kill(pid, SIG) == -1)
		return (9);

	fds[0].fd = mfd;
	fds[1].fd = sfd;
	fds[0].events = fds[1].events = POLLIN;
	fds[0].revents = fds[1].revents = 0;
	if (poll(fds, array_sizeof(fds), TIME * 1000 /* msec */) != 1)
		return (10);
	if ((fds[0].revents & POLLIN) != 0)
		return (11);
	if ((fds[1].revents & POLLIN) == 0)
		return (12);

	if (wait4(pid, &status, 0, NULL) == -1)
		return (13);
	if (!WIFEXITED(status))
		return (14);
	child_status = WEXITSTATUS(status);
	if (child_status != 0)
		return (32 + child_status);

	return (0);
}

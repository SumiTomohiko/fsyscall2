
#define	SIG	SIGUSR1
#define	R	0
#define	W	1

static const char datum = '*';

static int
child_main(pid_t ppid, int fds[2])
{
	int wfd;

	if (close(fds[R]) == -1)
		return (1);
	wfd = fds[W];
	if (write(wfd, &datum, sizeof(datum)) != sizeof(datum))
		return (2);
	if (kill(ppid, SIG) == -1)
		return (3);
	if (close(wfd) == -1)
		return (4);

	return (0);
}

int
main(int argc, const char *argv[])
{
	struct timeval timeout;
	sigset_t set;
	fd_set readfds;
	pid_t pid, ppid;
	int child_status, fds[2], rfd, sig, status;
	char buf;

	if (sigfillset(&set) == -1)
		return (1);
	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		return (2);
	if (pipe(fds) == -1)
		return (3);
	ppid = getpid();

	pid = fork();
	if (pid == -1)
		return (4);
	if (pid == 0) {
		child_status = child_main(ppid, fds);
		return (child_status == 0 ? child_status : 64 + child_status);
	}

	if (close(fds[W]) == -1)
		return (5);
	if (sigwait(&set, &sig) != 0)
		return (6);
	if (sig != SIG)
		return (7);
	rfd = fds[R];
	FD_ZERO(&readfds);
	FD_SET(rfd, &readfds);
	timeout.tv_sec = timeout.tv_usec = 0;
	if (select(rfd + 1, &readfds, NULL, NULL, &timeout) != 1)
		return (8);
	if (!FD_ISSET(rfd, &readfds))
		return (9);
	if (read(rfd, &buf, sizeof(buf)) != sizeof(buf))
		return (10);
	if (buf != datum)
		return (11);
	if (close(rfd) == -1)
		return (12);
	if (wait4(pid, &status, 0, NULL) == -1)
		return (13);
	if (!WIFEXITED(status))
		return (14);
	if (WEXITSTATUS(status) != 0)
		return (WEXITSTATUS(status));

	return (0);
}

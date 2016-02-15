
#define	SIG	SIGUSR1

static int
child_main(const struct sockaddr *addr, pid_t ppid)
{
	struct timespec timeout;
	int fd, sock;
	char c;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	if (bind(sock, addr, addr->sa_len) == -1)
		return (2);
	if (listen(sock, 0) == -1)
		return (3);
	if (kill(ppid, SIG) == -1)
		return (4);
	fd = accept(sock, NULL, NULL);
	if (fd == -1)
		return (5);

	timeout.tv_sec = 2;
	timeout.tv_nsec = 0;
	if (nanosleep(&timeout, NULL) != 0)
		return (6);

	c = '*';
	if (write(fd, &c, sizeof(c)) != sizeof(c))
		return (7);

	close(fd);
	close(sock);

	return (0);
}

#define	R	0
#define	W	1

int
main(int argc, const char *argv[])
{
	struct sockaddr_storage addr;
	struct sockaddr_un *paddr;
	sigset_t set;
	struct pollfd fds[2];
	pid_t pid, ppid;
	int fildes[2], sig, sock, status;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	paddr = (struct sockaddr_un *)&addr;
	paddr->sun_family = AF_UNIX;
	strcpy(paddr->sun_path, path);
	paddr->sun_len = SUN_LEN(paddr);

	if (sigfillset(&set) != 0)
		return (2);

	ppid = getpid();
	pid = fork();
	switch (pid) {
	case -1:
		return (3);
	case 0:
		return (child_main((struct sockaddr *)paddr, ppid));
	default:
		break;
	}

	if (sigwait(&set, &sig) != 0)
		return (4);
	if (sig != SIG)
		return (5);

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
		return (6);
	if (connect(sock, (struct sockaddr *)paddr, paddr->sun_len) == -1)
		return (7);

	if (pipe(fildes) == -1)
		return (8);

	fds[0].fd = sock;
	fds[0].events = POLLIN;
	fds[1].fd = fildes[R];
	fds[1].events = POLLIN;
	fds[0].revents = fds[1].revents = 0;
	if (poll(fds, array_sizeof(fds), 0) != 0)
		return (9);
	if (fds[0].revents != 0)
		return (10);
	if (fds[1].revents != 0)
		return (11);
	if (wait4(pid, &status, 0, NULL) != pid)
		return (12);
	if (!WIFEXITED(status))
		return (13);
	if (WEXITSTATUS(status) != 0)
		return (64 + WEXITSTATUS(status));

	return (0);
}

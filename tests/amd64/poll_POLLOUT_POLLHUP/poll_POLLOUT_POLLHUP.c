
#define	SIG	SIGUSR1

static int
child_main(const struct sockaddr *addr)
{
	struct pollfd fd;
	sigset_t set;
	int sig, sock;
	char c;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	if (sigemptyset(&set) == -1)
		return (2);
	if (sigaddset(&set, SIG) == -1)
		return (3);
	if (sigwait(&set, &sig) != 0)
		return (4);

	if (connect(sock, addr, addr->sa_len) == -1)
		return (6);
	if (sigwait(&set, &sig) != 0)
		return (7);
	fd.fd = sock;
	fd.events = POLLOUT;
	fd.revents = 0;
	if (poll(&fd, 1, 0) != 1)
		return (9);
	if (fd.revents != POLLHUP)
		return (10);

	if (close(sock) == -1)
		return (14);

	return (0);
}

static int
parent_main(const struct sockaddr *addr, pid_t pid)
{
	int fd, sock;
	char c;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	if (bind(sock, addr, addr->sa_len) == -1)
		return (2);
	if (listen(sock, 0) == -1)
		return (3);
	if (kill(pid, SIG) == -1)
		return (4);

	fd = accept(sock, NULL, 0);
	if (fd == -1)
		return (5);
	if (close(fd) == -1)
		return (7);
	if (kill(pid, SIG) == -1)
		return (8);

	if (close(sock) == -1)
		return (9);

	return (0);
}

int
main(int argc, const char *argv[])
{
	struct sockaddr_storage addr;
	struct sockaddr_un *paddr;
	sigset_t set;
	pid_t pid;
	int error, status;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	paddr = (struct sockaddr_un *)&addr;
	paddr->sun_family = AF_LOCAL;
	strcpy(paddr->sun_path, path);
	paddr->sun_len = SUN_LEN(paddr);

	if (sigfillset(&set) == -1)
		return (2);
	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		return (3);

	pid = fork();
	switch (pid) {
	case -1:
		return (4);
	case 0:
		return (child_main((struct sockaddr *)paddr));
	default:
		break;
	}

	error = parent_main((struct sockaddr *)paddr, pid);

	if (wait4(pid, &status, 0, NULL) == -1)
		return (5);
	if (!WIFEXITED(status))
		return (6);
	if (WEXITSTATUS(status) != 0)
		return (64 + WEXITSTATUS(status));

	return (error == 0 ? 0 : (32 + error));
}

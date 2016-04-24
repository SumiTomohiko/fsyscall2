
#define	SIG	SIGUSR1

static int
client_main(const struct sockaddr *addr)
{
	sigset_t set;
	int flags, sig, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	if (fcntl(sock, F_SETFL, O_NONBLOCK) == -1)
		return (2);

	if (sigemptyset(&set) == -1)
		return (3);
	if (sigaddset(&set, SIG) == -1)
		return (4);
	if (sigwait(&set, &sig) != 0)
		return (5);

	if (connect(sock, addr, addr->sa_len) == -1)
		return (6);
	flags = O_NONBLOCK | O_APPEND | O_DIRECT | O_ASYNC;
	if ((fcntl(sock, F_GETFL) & flags) != O_NONBLOCK)
		return (7);

	if (close(sock) == -1)
		return (8);

	return (0);
}

static int
server_main(const struct sockaddr *addr, pid_t pid)
{
	int fd, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	if (bind(sock, addr, addr->sa_len) == -1)
		return (3);
	if (listen(sock, 0) == -1)
		return (4);
	if (kill(pid, SIG) == -1)
		return (5);
	if ((fd = accept(sock, NULL, 0)) == -1)
		return (6);
	if (close(fd) == -1)
		return (7);
	if (close(sock) == -1)
		return (8);

	return (0);
}

int
main(int argc, const char *argv[])
{
	struct sockaddr_un addr;
	struct sockaddr *paddr;
	sigset_t set;
	pid_t pid;
	int retval, status;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, path);
	addr.sun_len = SUN_LEN(&addr);
	paddr = (struct sockaddr *)&addr;

	if (sigemptyset(&set) == -1)
		return (2);
	if (sigaddset(&set, SIG) == -1)
		return (3);
	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		return (4);

	pid = fork();
	switch (pid) {
	case -1:
		return (5);
	case 0:
		return (client_main(paddr));
	default:
		break;
	}

	retval = server_main(paddr, pid);
	if (wait4(pid, &status, 0, NULL) == -1)
		return (6);
	if (!WIFEXITED(status))
		return (7);
	if (WEXITSTATUS(status) != 0)
		return (64 + WEXITSTATUS(status));

	return (retval);
}

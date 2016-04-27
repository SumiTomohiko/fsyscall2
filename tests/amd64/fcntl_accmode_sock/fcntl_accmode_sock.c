
#define	SIG	SIGUSR1

static int
server_main(const struct sockaddr *addr, pid_t pid)
{
	int fd, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
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
		return (6);
	if (close(sock) == -1)
		return (7);

	return (0);
}

static int
client_main(const struct sockaddr *addr)
{
	sigset_t set;
	int flags, sig, sock;

	if (sigemptyset(&set) == -1)
		return (1);
	if (sigaddset(&set, SIG) == -1)
		return (2);
	if (sigwait(&set, &sig) != 0)
		return (3);
	if (sig != SIG)
		return (4);

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (5);
	if (connect(sock, addr, addr->sa_len) == -1)
		return (6);
	flags = fcntl(sock, F_GETFL);
	if (flags == -1)
		return (7);
	if ((O_ACCMODE & flags) != O_RDWR)
		return (8);
	if (close(sock) == -1)
		return (9);

	return (0);
}

int
main(int argc, const char *argv[])
{
	struct sockaddr_un addr;
	const struct sockaddr *paddr;
	sigset_t set;
	pid_t pid;
	int flags, retval, sock, status;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	if (sigemptyset(&set) == -1)
		return (2);
	if (sigaddset(&set, SIG) == -1)
		return (3);
	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		return (4);

	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, path);
	addr.sun_len = SUN_LEN(&addr);
	paddr = (const struct sockaddr *)&addr;

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

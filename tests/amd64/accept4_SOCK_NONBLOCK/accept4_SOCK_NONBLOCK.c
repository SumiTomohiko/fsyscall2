
#define	SIG	SIGUSR1

static int
server_main(const struct sockaddr *addr, pid_t pid)
{
	int d, flags, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	if (bind(sock, addr, addr->sa_len) == -1)
		return (2);
	if (listen(sock, 0) == -1)
		return (3);
	if (kill(pid, SIG) == -1)
		return (4);

	d = accept4(sock, NULL, NULL, SOCK_NONBLOCK);
	if (d == -1)
		return (7);
	flags = fcntl(d, F_GETFL);
	if (flags == -1)
		return (8);
	if ((flags & O_NONBLOCK) == 0)
		return (9);

	if (close(d) == -1)
		return (5);
	if (close(sock) == -1)
		return (6);

	return (0);
}

static int
client_main(const struct sockaddr *addr)
{
	sigset_t set;
	int sig, sock;
	char c;

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

	if (close(sock) == -1)
		return (7);

	return (0);
}

int
main(int argc, const char *argv[])
{
	struct sockaddr_storage addr;
	struct sockaddr_un *paddr;
	sigset_t set;
	pid_t pid;
	int retval, status;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	paddr = (struct sockaddr_un *)&addr;
	paddr->sun_family = AF_LOCAL;
	strcpy(paddr->sun_path, path);
	paddr->sun_len = SUN_LEN(paddr);

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
		return (client_main((struct sockaddr *)paddr));
	default:
		break;
	}

	retval = server_main((struct sockaddr *)paddr, pid);
	if (retval != 0)
		kill(pid, SIGKILL);

	if (wait4(pid, &status, 0, NULL) == -1)
		return (6);
	if (!WIFEXITED(status))
		return (7);
	if (WEXITSTATUS(status) != 0)
		return (64 + WEXITSTATUS(status));

	return (retval == 0 ? retval : 32 + retval);
}

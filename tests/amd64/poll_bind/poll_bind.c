
static struct sockaddr_storage addr;
static struct sockaddr_storage addr2;

static int
child_main(sigset_t *set, struct sockaddr *paddr)
{
	int sig, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);

	if (sigwait(set, &sig) != 0)
		return (2);
	if (sig != SIGUSR1)
		return (3);

	if (connect(sock, paddr, paddr->sa_len) == -1)
		return (4);

	return (0);
}

int
main(int argc, const char *argv[])
{
	struct sockaddr_un *paddr;
	struct pollfd fd;
	sigset_t set;
	pid_t pid;
	socklen_t len;
	int n, sock, status;
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
	if (pid == -1)
		return (4);
	if (pid == 0)
		return (child_main(&set, (struct sockaddr *)paddr));

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (4);
	if (bind(sock, (struct sockaddr *)paddr, paddr->sun_len) == -1)
		return (5);
	if (listen(sock, 32) == -1)
		return (6);
	if (kill(pid, SIGUSR1) == -1)
		return (7);

	fd.fd = sock;
	fd.events = POLL_IN;
	fd.revents = 0;
	if ((n = poll(&fd, 1, 10000 /* msec */)) == -1)
		return (8);
	if (n != 1)
		return (9);
	len = sizeof(addr2);
	if (accept(sock, (struct sockaddr *)&addr2, &len) == -1)
		return (10);

	if (wait4(pid, &status, 0, NULL) == -1)
		return (11);
	if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0))
		return (12);
	if (unlink(paddr->sun_path) == -1)
		return (13);

	return (0);
}


static struct sockaddr_storage addr;
static struct sockaddr_storage client_addr;

static void
signal_handler(int sig)
{
}

#define	SIGNAL	SIGUSR1

static int
client_main(struct sockaddr *paddr)
{
	sigset_t oset, set;
	int error, sig, sock;

	if (sigemptyset(&set) == -1)
		return (4);
	if (sigaddset(&set, SIGNAL) == -1)
		return (5);
	if (sigwait(&set, &sig) != 0)
		return (6);

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (3);
	error = connect(sock, paddr, paddr->sa_len);
	if (error == -1)
		return (1);
	error = close(sock);
	if (error == -1)
		return (2);

	return (0);
}

static int
server_main(pid_t pid, struct sockaddr *paddr)
{
	socklen_t addrlen;
	int error, fd, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (6);
	if (bind(sock, paddr, paddr->sa_len) == -1)
		return (1);
	if (listen(sock, 0) == -1)
		return (2);
	if (kill(pid, SIGNAL) == -1)
		return (7);
	addrlen = sizeof(client_addr);
	fd = accept(sock, (struct sockaddr *)&client_addr, &addrlen);
	if (fd == -1)
		return (3);
	if (close(fd) == -1)
		return (4);
	if (close(sock) == -1)
		return (5);

	return (0);
}

int
main(int argc, const char *argv[])
{
	struct sigaction act;
	struct sockaddr_un *paddr;
	sigset_t set;
	pid_t pid;
	int error, retval, status;

	act.sa_handler = signal_handler;
	act.sa_flags = 0;
	if (sigemptyset(&act.sa_mask) == -1)
		return (8);
	if (sigaction(SIGNAL, &act, NULL) == -1)
		return (9);
	if (sigemptyset(&set) == -1)
		return (4);
	if (sigaddset(&set, SIGNAL) == -1)
		return (5);
	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		return (7);

	paddr = (struct sockaddr_un *)&addr;
	paddr->sun_family = AF_LOCAL;
	strcpy(paddr->sun_path, argv[1]);
	paddr->sun_len = SUN_LEN(paddr);

	pid = fork();
	switch (pid) {
	case -1:
		return (64);
	case 0:
		return (client_main((struct sockaddr *)paddr));
	default:
		break;
	}

	retval = server_main(pid, (struct sockaddr *)paddr);
	error = wait4(pid, &status, 0, NULL);
	if (error == -1)
		return (66);
	if (!WIFEXITED(status))
		return (67);
	if (WEXITSTATUS(status) != 0)
		return (68);

	return (retval);
}

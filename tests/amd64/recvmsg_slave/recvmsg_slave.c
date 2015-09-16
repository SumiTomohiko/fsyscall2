
#define	SIG	SIGUSR1

static char datum = '*';

static int
client_main(const char *sockpath)
{
	struct sockaddr_storage sockaddr;
	struct sockaddr_un *addr;
	sigset_t set;
	int sig, sock;

	if (sigaddset(&set, SIG) == -1)
		return (1);
	if (sigwait(&set, &sig) != 0)
		return (2);
	if (sig != SIG)
		return (3);

	sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (4);
	addr = (struct sockaddr_un *)&sockaddr;
	addr->sun_family = AF_LOCAL;
	strcpy(addr->sun_path, sockpath);
	addr->sun_len = SUN_LEN(addr);
	if (connect(sock, (struct sockaddr *)addr, addr->sun_len) == -1)
		return (5);

	if (write(sock, &datum, sizeof(datum)) != sizeof(datum))
		return (6);

	if (close(sock) == -1)
		return (8);

	return (0);
}

static int
server_main(const char *sockpath, pid_t pid)
{
	struct sockaddr_storage name, sockaddr;
	struct sockaddr_un *addr;
	struct msghdr msg;
	struct iovec iov;
	socklen_t namelen;
	int s, sock;
	char buf[1];

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	addr = (struct sockaddr_un *)&sockaddr;
	addr->sun_family = AF_LOCAL;
	strcpy(addr->sun_path, sockpath);
	addr->sun_len = SUN_LEN(addr);
	if (bind(sock, (struct sockaddr *)addr, addr->sun_len) == -1)
		return (2);
	if (listen(sock, 0) == -1)
		return (3);
	if (kill(pid, SIG) == -1)
		return (4);
	namelen = sizeof(name);
	if ((s = accept(sock, (struct sockaddr *)&name, &namelen)) == -1)
		return (5);

	if (tr_wait_data(s) == -1)
		return (6);
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	if (recvmsg(s, &msg, 0) != sizeof(datum))
		return (7);
	if (datum != buf[0])
		return (8);

	if (close(s) == -1)
		return (9);
	if (close(sock) == -1)
		return (10);

	return (0);
}

int
main(int argc, const char *argv[])
{
	sigset_t oset, set;
	pid_t pid;
	int retval, status;
	const char *sockpath;

	if (argc < 2)
		return (1);
	sockpath = argv[1];

	if (sigfillset(&set) == -1)
		return (2);
	if (sigprocmask(SIG_BLOCK, &set, &oset) == -1)
		return (3);

	pid = fork();
	if (pid == -1)
		return (4);
	if (pid == 0)
		return (client_main(sockpath));

	retval = server_main(sockpath, pid);

	if (wait4(pid, &status, 0, NULL) == -1)
		return (5);
	if (!WIFEXITED(status))
		return (6);
	if (WEXITSTATUS(status) != 0)
		return (64 + WEXITSTATUS(status));

	return (retval == 0 ? 0 : 32 + retval);
}

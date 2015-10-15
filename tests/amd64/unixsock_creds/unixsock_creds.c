
#define	SIG	SIGUSR1

static char datum = '*';

static int
do_sendmsg(int fd)
{
	struct msghdr msg;
	struct cmsghdr *cmsghdr;
	struct cmsgcred *cmsgcred;
	struct iovec iov[1];
	ssize_t nbytes;
	int i;
	char buf[CMSG_SPACE(0)], c;

	c = datum;
	iov[0].iov_base = &c;
	iov[0].iov_len = sizeof(c);
	cmsghdr = (struct cmsghdr *)buf;
	cmsghdr->cmsg_len = CMSG_LEN(0);
	cmsghdr->cmsg_level = SOL_SOCKET;
	cmsghdr->cmsg_type = SCM_CREDS;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
	msg.msg_control = cmsghdr;
	msg.msg_controllen = sizeof(buf);
	msg.msg_flags = 0;

	nbytes = sendmsg(fd, &msg, 0);
	if (nbytes != sizeof(c))
		return (1);

	return (0);
}

static int
server_main(pid_t ppid, const char *sockpath)
{
	struct sockaddr_storage name, storage;
	struct sockaddr_un *addr;
	socklen_t namelen;
	int error, level, optname, optval, s, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	level = SOL_SOCKET;
	optname = SO_REUSEADDR;
	optval = 1;
	if (setsockopt(sock, level, optname, &optval, sizeof(optval)) == -1)
		return (2);
	addr = (struct sockaddr_un *)&storage;
	addr->sun_family = AF_LOCAL;
	strcpy(addr->sun_path, sockpath);
	addr->sun_len = SUN_LEN(addr);
	if (bind(sock, (struct sockaddr *)addr, addr->sun_len) == -1)
		return (3);
	if (listen(sock, 0) == -1)
		return (4);
	if (kill(ppid, SIG) == -1)
		return (5);
	namelen = sizeof(name);
	if ((s = accept(sock, (struct sockaddr *)&name, &namelen)) == -1)
		return (6);

	if (do_sendmsg(s) != 0)
		return (7);

	if (close(s) == -1)
		return (8);
	if (close(sock) == -1)
		return (9);
	if (unlink(sockpath) == -1)
		return (10);

	return (0);
}

static int
do_recvmsg(int fd)
{
	struct msghdr msg;
	struct cmsghdr *cmsghdr;
	struct cmsgcred *cmsgcred;
	struct iovec iov[1];
	ssize_t nbytes;
	int i;
	char buf[CMSG_SPACE(sizeof(struct cmsgcred))], c;

	iov[0].iov_base = &c;
	iov[0].iov_len = sizeof(c);
	bzero(buf, sizeof(buf));
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
	msg.msg_control = (struct cmsghdr *)buf;
	msg.msg_controllen = sizeof(buf);
	msg.msg_flags = 0;

	nbytes = recvmsg(fd, &msg, 0);

	return ((nbytes == sizeof(c)) && (c == datum) ? 0 : -1);
}

static int
client_main(pid_t pid, const char *sockpath)
{
	struct sockaddr_storage sockaddr;
	struct sockaddr_un *addr;
	sigset_t set;
	int sig, sock, status;
	const char *signame;

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
	addr = (struct sockaddr_un *)&sockaddr;
	addr->sun_family = AF_LOCAL;
	strcpy(addr->sun_path, sockpath);
	addr->sun_len = SUN_LEN(addr);
	if (connect(sock, (struct sockaddr *)addr, addr->sun_len) == -1)
		return (6);
	if (do_recvmsg(sock) == -1)
		return (7);
	if (close(sock) == -1)
		return (8);

	return (0);
}

int
main(int argc, const char *argv[])
{
	sigset_t set;
	pid_t pid, ppid;
	int n, status;
	const char *sockpath;

	if (argc < 2)
		return (1);
	sockpath = argv[1];

	if (sigfillset(&set) == -1)
		return (2);
	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		return (3);

	ppid = getpid();
	pid = fork();
	switch (pid) {
	case -1:
		return (4);
	case 0:
		return (server_main(ppid, sockpath));
	default:
		break;
	}

	n = client_main(pid, sockpath);

	if (wait4(pid, &status, 0, NULL) == -1)
		return (5);
	if (!WIFEXITED(status))
		return (6);
	if (WEXITSTATUS(status) != 0)
		return (64 + WEXITSTATUS(status));

	return (n + (n == 0 ? 0 : 32));
}

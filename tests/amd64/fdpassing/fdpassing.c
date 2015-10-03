
#define	SIG	SIGUSR1

static int
do_sendmsg(int sock, int fd)
{
	struct msghdr msg;
	struct cmsghdr *cmsghdr;
	struct iovec iov[1];
	ssize_t nbytes;
	int i, *p;
	char buf[CMSG_SPACE(sizeof(int))], c;

	c = '*';
	iov[0].iov_base = &c;
	iov[0].iov_len = sizeof(c);
	memset(buf, 0x0b, sizeof(buf));
	cmsghdr = (struct cmsghdr *)buf;
	cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
	cmsghdr->cmsg_level = SOL_SOCKET;
	cmsghdr->cmsg_type = SCM_RIGHTS;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
	msg.msg_control = cmsghdr;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	msg.msg_flags = 0;
	p = (int *)CMSG_DATA(buf);
	*p = fd;

	nbytes = sendmsg(sock, &msg, 0);
	if (nbytes == -1)
		return (1);

	return (0);
}

static int
server_main(pid_t ppid, const char *sockpath, const char *filepath)
{
	struct sockaddr_storage storage;
	struct sockaddr_un *addr;
	int error, fd, s, sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	addr = (struct sockaddr_un *)&storage;
	addr->sun_family = AF_LOCAL;
	strcpy(addr->sun_path, sockpath);
	addr->sun_len = SUN_LEN(addr);
	if (bind(sock, (struct sockaddr *)addr, addr->sun_len) == -1)
		return (2);
	if (listen(sock, 0) == -1)
		return (3);
	if (kill(ppid, SIG) == -1)
		return (4);
	if ((s = accept(sock, NULL, 0)) == -1)
		return (5);
	if ((fd = open(filepath, O_WRONLY | O_CREAT, 0644)) == -1)
		return (7);

	if (do_sendmsg(s, fd) != 0)
		return (8);

	if (close(fd) == -1)
		return (9);
	if (close(s) == -1)
		return (10);
	if (close(sock) == -1)
		return (11);

	return (0);
}

static int
do_recvmsg(int sock, const char *s)
{
	struct msghdr msg;
	struct cmsghdr *cmsghdr;
	struct iovec iov[1];
	ssize_t nbytes;
	int fd, i, level, *p, type;
	char buf[CMSG_SPACE(sizeof(int))], c;

	iov[0].iov_base = &c;
	iov[0].iov_len = sizeof(c);
	memset(buf, 0x0d, sizeof(buf));
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
	msg.msg_control = (struct cmsghdr *)buf;
	msg.msg_controllen = sizeof(buf);
	msg.msg_flags = 0;

	nbytes = recvmsg(sock, &msg, 0);
	if (nbytes == -1)
		return (1);

	for (cmsghdr = CMSG_FIRSTHDR(&msg);
	     cmsghdr != NULL;
	     cmsghdr = CMSG_NXTHDR(&msg, cmsghdr)) {
		switch (cmsghdr->cmsg_level) {
		case SOL_SOCKET:
			switch (cmsghdr->cmsg_type) {
			case SCM_RIGHTS:
				p = (int *)CMSG_DATA(cmsghdr);
				fd = *p;
				write(fd, s, strlen(s));
				if (close(fd) == -1)
					return (2);
				break;
			default:
				return (3);
			}
			break;
		default:
			return (4);
		}
	}

	return (0);
}

static int
client_main(const char *sockpath, const char *msg)
{
	struct sockaddr_storage sockaddr;
	struct sockaddr_un *addr;
	sigset_t set;
	int sig, sock;
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

	if (do_recvmsg(sock, msg) == -1)
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
	int exitstatus, status;
	const char *filepath, *msg, *sockpath;

	if (argc < 4)
		return (1);
	sockpath = argv[1];
	filepath = argv[2];
	msg = argv[3];

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
		return (server_main(ppid, sockpath, filepath));
	default:
		break;
	}

	exitstatus = client_main(sockpath, msg);

	if (wait4(pid, &status, 0, NULL) == -1)
		return (5);
	if (!WIFEXITED(status))
		return (6);
	if (WEXITSTATUS(status) != 0)
		return (32 + WEXITSTATUS(status));

	return (exitstatus == 0 ? 0 : 64 + exitstatus);
}


#define	SIG	SIGUSR1

static int
do_sendmsg(int sock, int fd1, int fd2)
{
#define	DATASIZE	(2 * sizeof(int))
	struct msghdr msg;
	struct cmsghdr *cmsghdr;
	struct iovec iov[1];
	ssize_t nbytes;
	socklen_t len;
	int i, *p;
	char buf[CMSG_SPACE(DATASIZE)], c;

	c = '*';
	iov[0].iov_base = &c;
	iov[0].iov_len = sizeof(c);
	memset(buf, 0x0b, sizeof(buf));
	len = CMSG_LEN(DATASIZE);
	cmsghdr = (struct cmsghdr *)buf;
	cmsghdr->cmsg_len = len;
	cmsghdr->cmsg_level = SOL_SOCKET;
	cmsghdr->cmsg_type = SCM_RIGHTS;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
	msg.msg_control = cmsghdr;
	msg.msg_controllen = sizeof(buf);
	msg.msg_flags = 0;
	p = (int *)CMSG_DATA(buf);
	p[0] = fd1;
	p[1] = fd2;

	nbytes = sendmsg(sock, &msg, 0);
	if (nbytes == -1)
		return (1);

	return (0);
#undef	DATASIZE
}

static int
server_main(pid_t ppid, const char *sockpath, const char *filepath1,
	    const char *filepath2)
{
	struct sockaddr_storage storage;
	struct sockaddr_un *addr;
	int error, fd1, fd2, s, sock;

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
	if ((fd1 = open(filepath1, O_WRONLY | O_CREAT, 0644)) == -1)
		return (7);
	if ((fd2 = open(filepath2, O_WRONLY | O_CREAT, 0644)) == -1)
		return (8);

	if (do_sendmsg(s, fd1, fd2) != 0)
		return (9);

	if (close(fd2) == -1)
		return (10);
	if (close(fd1) == -1)
		return (11);
	if (close(s) == -1)
		return (12);
	if (close(sock) == -1)
		return (13);

	return (0);
}

static int
do_recvmsg(int sock, const char *s1, const char *s2)
{
	struct msghdr msg;
	struct cmsghdr *cmsghdr;
	struct iovec iov[1];
	ssize_t nbytes;
	int fd, i, level, *p, type;
	const char **ptext, *s, *texts[2];
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

	texts[0] = s1;
	texts[1] = s2;
	ptext = &texts[0];
	for (cmsghdr = CMSG_FIRSTHDR(&msg);
	     cmsghdr != NULL;
	     cmsghdr = CMSG_NXTHDR(&msg, cmsghdr)) {
		switch (cmsghdr->cmsg_level) {
		case SOL_SOCKET:
			switch (cmsghdr->cmsg_type) {
			case SCM_RIGHTS:
				p = (int *)CMSG_DATA(cmsghdr);
				fd = *p;
				s = *ptext;
				write(fd, s, strlen(s));
				if (close(fd) == -1)
					return (2);
				ptext++;
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
client_main(const char *sockpath, const char *msg1, const char *msg2)
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

	if (do_recvmsg(sock, msg1, msg2) == -1)
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
	const char *filepath1, *filepath2, *msg1, *msg2, *sockpath;

	if (argc < 6)
		return (1);
	sockpath = argv[1];
	filepath1 = argv[2];
	msg1 = argv[3];
	filepath2 = argv[4];
	msg2 = argv[5];

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
		return (server_main(ppid, sockpath, filepath1, filepath2));
	default:
		break;
	}

	exitstatus = client_main(sockpath, msg1, msg2);

	if (wait4(pid, &status, 0, NULL) == -1)
		return (5);
	if (!WIFEXITED(status))
		return (6);
	if (WEXITSTATUS(status) != 0)
		return (32 + WEXITSTATUS(status));

	return (exitstatus == 0 ? 0 : 64 + exitstatus);
}

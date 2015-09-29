
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
	if (nbytes != -1)
		return (1);
	if (errno != EBADF)
		return (2);

	return (0);
}

const char datum = '*';

static int
server_main(int wpipe, pid_t ppid, const char *sockpath)
{
	struct sockaddr_storage storage;
	struct sockaddr_un *addr;
	struct stat sb;
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
	if (write(wpipe, &datum, sizeof(datum)) != sizeof(datum))
		return (4);
	if ((s = accept(sock, NULL, 0)) == -1)
		return (5);

	fd = 42;
	/* ensures that the fd is dead */
	if ((fstat(fd, &sb) != -1) && (errno != EBADF))
		return (6);
	if (do_sendmsg(s, fd) != 0)
		return (8);
	if (write(wpipe, &datum, sizeof(datum)) != sizeof(datum))
		return (4);

	if (close(fd) == -1)
		return (10);
	if (close(s) == -1)
		return (11);
	if (close(sock) == -1)
		return (12);
	if (close(wpipe) == -1)
		return (13);

	return (0);
}

static int
wait_server(int fd)
{
	struct pollfd pollfd;
	char c;

	pollfd.fd = fd;
	pollfd.events = POLLIN;
	pollfd.revents = 0;
	if (poll(&pollfd, 1, 2000) != 1)
		return (1);
	if (read(fd, &c, sizeof(c)) != sizeof(c))
		return (2);
	if (c != datum)
		return (3);

	return (0);
}

static int
client_main(int rpipe, const char *sockpath, const char *msg)
{
	struct sockaddr_storage sockaddr;
	struct sockaddr_un *addr;
	int sock;

	if (wait_server(rpipe) != 0)
		return (3);

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (5);
	addr = (struct sockaddr_un *)&sockaddr;
	addr->sun_family = AF_LOCAL;
	strcpy(addr->sun_path, sockpath);
	addr->sun_len = SUN_LEN(addr);
	if (connect(sock, (struct sockaddr *)addr, addr->sun_len) == -1)
		return (6);

	if (wait_server(rpipe) != 0)
		return (7);

	if (close(sock) == -1)
		return (8);
	if (close(rpipe) == -1)
		return (9);

	return (0);
}

#define	R	0
#define	W	1

int
main(int argc, const char *argv[])
{
	sigset_t set;
	pid_t pid, ppid;
	int exitstatus, fds[2], status;
	const char *filepath, *msg, *sockpath;

	if (argc < 2)
		return (1);
	sockpath = argv[1];

	if (pipe(fds) == -1)
		return (2);

	ppid = getpid();
	pid = fork();
	switch (pid) {
	case -1:
		return (4);
	case 0:
		if (close(fds[R]) == -1)
			return (5);
		return (server_main(fds[W], ppid, sockpath));
	default:
		break;
	}

	if (close(fds[W]) == -1)
		return (5);
	exitstatus = client_main(fds[R], sockpath, msg);

	if (wait4(pid, &status, 0, NULL) == -1)
		return (6);
	if (!WIFEXITED(status))
		return (7);
	if (WEXITSTATUS(status) != 0)
		return (32 + WEXITSTATUS(status));

	return (exitstatus == 0 ? 0 : 64 + exitstatus);
}

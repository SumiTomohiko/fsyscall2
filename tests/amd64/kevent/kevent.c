
#define	MODE	0644
#define	SIGNAL	SIGUSR1

static int
child_main(const char *path)
{
	sigset_t *pset, set;
	int fd, sig;
	const char data[] = "hogehoge";

	pset = &set;
	if (sigemptyset(pset) == -1)
		return (1);
	if (sigaddset(pset, SIGNAL) == -1)
		return (2);
	if (sigprocmask(SIG_BLOCK, pset, NULL) == -1)
		return (3);
	if (sigwait(pset, &sig) != 0)
		return (4);
	if (sig != SIGNAL)
		return (5);

	fd = open(path, O_WRONLY | O_CREAT, MODE);
	if (fd == -1)
		return (6);
	if (write(fd, data, strlen(data)) == -1)
		return (7);
	if (close(fd) == -1)
		return (8);

	return (0);
}

static int
main_for_kq(int fd, int kq, pid_t pid)
{
	struct kevent kev, kev2;
	u_int fflags;
	u_short flags;

	flags = EV_ADD | EV_ENABLE | EV_CLEAR;
	fflags = NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_RENAME;
	EV_SET(&kev, fd, EVFILT_VNODE, flags, fflags, 0, NULL);
	if (kevent(kq, &kev, 1, NULL, 0, NULL) == -1)
		return (1);
	if (kill(pid, SIGNAL) == -1)
		return (2);
	if (kevent(kq, NULL, 0, &kev2, 1, NULL) != 1)
		return (3);

	return (0);
}

static int
main_for_fd(int fd, pid_t pid)
{
	int kq, status;

	kq = kqueue();
	if (kq == -1)
		return (1);

	status = main_for_kq(fd, kq, pid);

	if (close(kq) == -1)
		return (2);

	return (status == 0 ? 0 : 32 + status);
}

static int
parent_main(const char *path, pid_t pid)
{
	int fd, status;

	fd = open(path, O_RDONLY | O_CREAT, MODE);
	if (fd == -1)
		return (1);

	status = main_for_fd(fd, pid);

	if (close(fd) == -1)
		return (2);

	return (status == 0 ? 0 : 16 + status);
}

int
main(int argc, const char *argv[])
{
	sigset_t *pset, set;
	pid_t pid;
	int status;
	const char *path;

	if (argc < 2)
		return (1);
	path = argv[1];

	pset = &set;
	if (sigemptyset(pset) == -1)
		return (2);
	if (sigaddset(pset, SIGNAL) == -1)
		return (3);
	if (sigprocmask(SIG_BLOCK, pset, NULL) == -1)
		return (4);

	pid = fork();
	if (pid == -1)
		return (4);
	if (pid == 0)
		return ((status = child_main(path)) == 0 ? 0 : 64 + status);

	return ((status = parent_main(path, pid)) == 0 ? 0 : 128 + status);
}

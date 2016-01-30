
static int
parent_main(pid_t child_pid)
{
	pid_t pid;
	int status;

	pid = wait4(child_pid, &status, WNOHANG, NULL);
	if (pid != 0)
		return (1);

	return (0);
}

static void
signal_handler(int sig)
{
}

int
main(int argc, const char *argv[])
{
	struct sigaction act;
	struct timespec t;
	pid_t child_pid;
	int retval;

	act.sa_handler = signal_handler;
	act.sa_flags = 0;
	if (sigfillset(&act.sa_mask) == -1)
		return (16);
	if (sigaction(SIGTERM, &act, NULL) == -1)
		return (17);

	child_pid = fork();
	switch (child_pid) {
	case -1:
		return (18);
	case 0:
		t.tv_sec = 8;
		t.tv_nsec = 0;
		nanosleep(&t, NULL);
		return (0);
	default:
		break;
	}

	retval = parent_main(child_pid);

	kill(child_pid, SIGTERM);

	return (retval);
}

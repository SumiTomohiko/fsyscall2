
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

int
main(int argc, const char *argv[])
{
	pid_t child_pid;
	int retval;

	child_pid = fork();
	switch (child_pid) {
	case -1:
		return (18);
	case 0:
		for (;;)
			;
		return (0);
	default:
		break;
	}

	retval = parent_main(child_pid);

	kill(child_pid, SIGKILL);

	return (retval);
}

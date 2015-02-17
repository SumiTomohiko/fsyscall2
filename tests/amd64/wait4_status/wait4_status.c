
int
main(int argc, const char *argv[])
{
	pid_t pid, retval;
	int status;

	pid = fork();
	switch (pid) {
	case -1:
		return (1);
	case 0:
		return (0);
	default:
		break;
	}

	retval = wait4(pid, &status, 0, NULL);
	if (retval == -1)
		return (2);

	return (WEXITSTATUS(status) == 0 ? 0 : 3);
}

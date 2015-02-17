
int
main(int argc, const char *argv[])
{
	pid_t pid, retval;
	struct rusage rusage;

	pid = fork();
	switch (pid) {
	case -1:
		return (1);
	case 0:
		return (0);
	default:
		break;
	}

	retval = wait4(pid, NULL, 0, &rusage);
	if (retval == -1)
		return (2);

	return (0);
}

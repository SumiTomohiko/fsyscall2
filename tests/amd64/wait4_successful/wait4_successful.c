
int
main(int argc, const char *argv[])
{
	pid_t pid, retval;

	pid = fork();
	switch (pid) {
	case -1:
		return (1);
	case 0:
		return (0);
	default:
		break;
	}

	retval = wait4(pid, NULL, 0, NULL);

	return (pid == retval ? 0 : 2);
}

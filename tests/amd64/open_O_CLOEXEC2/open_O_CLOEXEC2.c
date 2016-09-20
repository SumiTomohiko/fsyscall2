
static void
exec(char *path, char *n)
{
	char *args[3];

	args[0] = path;
	args[1] = n;
	args[2] = NULL;
	execve(args[0], args, NULL);
	/* NOTREACHED */
}

static int
first(char *path)
{
	int fd;

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd == -1)
		return (1);

	exec(path, "1");

	return (2);
}

static int
second(char *path)
{

	exec(path, "2");

	return (1);
}

int
main(int argc, char *argv[])
{
	int status;

	if (argc == 1) {
		status = first(argv[0]);
		return (status == 0 ? 0 : 8 + status);
	}
	switch (argv[1][0]) {
	case '1':
		status = second(argv[0]);
		return (status == 0 ? 0 : 16 + status);
	case '2':
		break;
	default:
		return (1);
	}

	return (0);
}


struct bonus {
	pid_t	pid;
	pid_t	retval;
	int	errnum;
};

static void *
start_routine(void *arg)
{
	struct bonus *bonus;

	bonus = (struct bonus *)arg;
	bonus->retval = wait4(bonus->pid, NULL, 0, NULL);
	bonus->errnum = errno;

	return (NULL);
}

int
main(int argc, const char *argv[])
{
	struct timespec t;
	struct bonus bonus;
	pthread_t thread;
	pid_t pid, retval;
	int errnum;

	pid = fork();
	switch (pid) {
	case -1:
		return (1);
	case 0:
		t.tv_sec = 4;
		t.tv_nsec = 0;
		nanosleep(&t, NULL);
		return (0);
	default:
		break;
	}

	bonus.pid = pid;
	if (pthread_create(&thread, NULL, start_routine, &bonus) != 0)
		return (2);

	retval = wait4(pid, NULL, 0, NULL);
	errnum = errno;

	if (pthread_join(thread, NULL) != 0)
		return (3);

	if ((retval != -1) && (bonus.retval == -1) && (bonus.errnum == ECHILD))
		;
	else if ((retval == -1) && (errnum == ECHILD) && (bonus.retval != -1))
		;
	else
		return (4);

	return (0);
}

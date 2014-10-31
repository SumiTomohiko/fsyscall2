#include <tiny_runtime.h>

#define	SIGNAL	SIGUSR1

static int
build_sigset(sigset_t *set)
{

	if (sigemptyset(set) == -1)
		return (128);
	if (sigaddset(set, SIGNAL) == -1)
		return (129);

	return (0);
}

static int
child_main()
{
	sigset_t set;
	int sig;

	if (build_sigset(&set) != 0)
		return (130);
	if (sigwait(&set, &sig) != 0)
		return (131);
	if (sig != SIGNAL)
		return (132);

	return (0);
}

static int
parent_main(pid_t pid)
{
	int status;

	if (kill(pid, SIGNAL) == -1)
		return (136);
	if (wait4(pid, &status, 0, NULL) == -1)
		return (137);
	if (!WIFEXITED(status))
		return (138);
	if (WEXITSTATUS(status) != 0)
		return (139);

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
	sigset_t set;
	pid_t pid;
	int error;

	act.sa_handler = signal_handler;
	act.sa_flags = 0;
	if (sigemptyset(&act.sa_mask) == -1)
		return (68);
	if (sigaction(SIGNAL, &act, NULL) == -1)
		return (64);
	if ((error = build_sigset(&set)) != 0)
		return (error);
	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		return (67);

	pid = fork();
	switch (pid) {
	case -1:
		return (68);
	case 0:
		return (child_main());
	default:
		break;
	}

	return (parent_main(pid));
}

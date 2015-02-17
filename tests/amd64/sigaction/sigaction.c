
static void
signal_handler(int sig, siginfo_t *info, void *ctx)
{
}

int
main(int argc, const char *argv[])
{
	struct sigaction act, oact;

	act.sa_sigaction = signal_handler;
	act.sa_flags = 0;
	if (sigemptyset(&act.sa_mask) == -1)
		return (1);
	if (sigaction(SIGUSR1, &act, &oact) == -1)
		return (2);

	return (0);
}

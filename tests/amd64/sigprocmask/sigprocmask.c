
int
main(int argc, const char *argv[])
{
	sigset_t set;

	if (sigemptyset(&set) == -1)
		return (1);
	if (sigaddset(&set, SIGUSR1) == -1)
		return (2);
	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		return (3);

	return (0);
}

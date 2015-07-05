
int
main(int argc, const char *argv[])
{
	sigset_t set;

	if (sigfillset(&set) == -1)
		return (1);
	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		return (3);

	return (0);
}

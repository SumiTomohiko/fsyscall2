
static int
test(int d)
{
	int flags;

	flags = fcntl(d, F_GETFD);
	if (flags == -1)
		return (1);
	if ((FD_CLOEXEC & flags) == 0)
		return (2);

	return (0);
}

int
main(int argc, const char *argv[])
{
	int i, status, sv[2];

	if (socketpair(PF_LOCAL, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) == -1)
		return (1);
	if ((status = test(sv[0])) != 0)
		return (16 + status);
	if ((status = test(sv[1])) != 0)
		return (32 + status);

	return (0);
}

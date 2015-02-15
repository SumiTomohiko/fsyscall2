
int
main(int argc, const char *argv[])
{
	socklen_t optlen2;
	int level, optname, optval, optval2, s;

	s = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (s == -1)
		return (1);
	level = SOL_SOCKET;
	optname = SO_REUSEADDR;
	optval = 1;
	if (setsockopt(s, level, optname, &optval, sizeof(optval)) == -1)
		return (2);
	optlen2 = sizeof(optval2);
	if (getsockopt(s, level, optname, &optval2, &optlen2) == -1)
		return (3);
	if (optlen2 != sizeof(optval2))
		return (4);
	if (optval2 == 0)
		return (5);

	return (0);
}

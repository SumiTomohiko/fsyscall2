
int
main(int argc, const char *argv[])
{
	socklen_t optlen;
	int optval, s;

	s = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (s == -1)
		return (1);
	optlen = sizeof(optval);
	if (getsockopt(s, SOL_SOCKET, SO_REUSEADDR, &optval, &optlen) != 0)
		return (2);
	if (optval != 0)
		return (3);
	if (optlen != sizeof(optval))
		return (4);

	return (0);
}


int
main(int argc, const char *argv[])
{
	struct statfs buf;
	int sock;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	if (fstatfs(sock, &buf) != -1)
		return (2);
	if (errno != EINVAL)
		return (3);

	return (0);
}

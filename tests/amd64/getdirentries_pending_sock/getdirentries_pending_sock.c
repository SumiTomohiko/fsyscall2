
int
main(int argc, const char *argv[])
{
	int sock;
	char buf[8192];

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (1);
	if (getdirentries(sock, buf, sizeof(buf), NULL) != -1)
		return (2);
	if (errno != EINVAL)
		return (3);

	return (0);
}

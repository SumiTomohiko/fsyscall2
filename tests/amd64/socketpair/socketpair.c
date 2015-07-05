
int
main(int argc, const char *argv[])
{
	int sv[2];

	return (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != -1 ? 0 : 1);
}

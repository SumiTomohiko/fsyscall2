
int
main(int argc, const char *argv[])
{
	return (fcntl(0, F_SETFD, 0));
}

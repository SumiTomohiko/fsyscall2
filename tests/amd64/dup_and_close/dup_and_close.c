
int
main(int argc, const char *argv[])
{
	int oldd, newd;
	const char *msg = argv[2];

	oldd = argv[1][0] - '0';
	newd = dup(oldd);
	close(newd);
	write(oldd, msg, strlen(msg));

	return (0);
}

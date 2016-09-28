
int
main(int argc, const char *argv[])
{
	size_t len;
	int d;
	const char *msg, *path;

	if (argc < 3)
		return (1);
	path = argv[1];
	msg = argv[2];

	d = open(path, O_RDWR | O_CREAT, 0644);
	if (d == -1)
		return (2);
	len = strlen(msg);
	if (write(d, msg, len) != len)
		return (3);

	return (0);
}

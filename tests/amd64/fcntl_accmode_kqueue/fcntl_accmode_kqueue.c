
int
main(int argc, const char *argv[])
{
	int flags, kq;

	kq = kqueue();
	if (kq == -1)
		return (1);
	flags = fcntl(kq, F_GETFL);
	if (flags == -1)
		return (2);

	return ((O_ACCMODE & flags) == O_RDWR ? 0 : 3);
}

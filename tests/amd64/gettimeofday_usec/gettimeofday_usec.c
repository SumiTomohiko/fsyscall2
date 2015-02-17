
int
main(int argc, const char *argv[])
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0)
		return (1);
	print_num(tv.tv_usec);

	return (0);
}

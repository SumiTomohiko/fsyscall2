
int
main(int argc, const char *argv[])
{
	mode_t mode;

	mode = umask(0400);

	return (mode != (mode_t)-1 ? 0 : 1);
}

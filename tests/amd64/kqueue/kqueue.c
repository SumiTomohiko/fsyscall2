
int
main(int argc, const char *argv[])
{

	return (kqueue() != -1 ? 0 : 1);
}

#include <tiny_runtime.h>

int
main(int argc, const char *argv[])
{
	print_num(geteuid());

	return (0);
}

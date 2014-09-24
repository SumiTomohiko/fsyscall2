#include <tiny_runtime.h>

int
main(int argc, const char *argv[])
{
	uid_t uid;

	if (getresuid(&uid, NULL, NULL) != 0)
		return (1);
	print_num(uid);

	return (0);
}
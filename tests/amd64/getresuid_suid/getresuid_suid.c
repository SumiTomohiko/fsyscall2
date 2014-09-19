#include <tiny_runtime.h>

int
main(int argc, const char *argv[])
{
	uid_t uid;

	if (getresuid(NULL, NULL, &uid) != 0)
		return (1);
	print_num(uid);

	return (0);
}

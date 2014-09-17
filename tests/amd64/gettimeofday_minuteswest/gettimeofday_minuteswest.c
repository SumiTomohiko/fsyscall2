#include <tiny_runtime.h>

int
main(int argc, const char *argv[])
{
	struct timezone tz;

	if (gettimeofday(NULL, &tz) != 0)
		return (1);
	print_num(tz.tz_minuteswest);

	return (0);
}

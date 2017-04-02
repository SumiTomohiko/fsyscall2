#include <time.h>

int
main(int argc, const char *argv[])
{
	struct timespec t;
	int status;

	t.tv_sec = 5 * 60;
	t.tv_nsec = 0;
	status = nanosleep(&t, NULL);

	return (status != -1 ? 0 : 1);
}

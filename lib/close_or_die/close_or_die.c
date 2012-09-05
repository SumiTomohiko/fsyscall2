#include <err.h>
#include <unistd.h>

void
close_or_die(int fd)
{
	if (close(fd) != 0)
		err(-1, "Cannot close");
}

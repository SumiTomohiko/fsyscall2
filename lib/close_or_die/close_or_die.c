#include <unistd.h>

#include <fsyscall/private/die.h>

void
close_or_die(int fd)
{
	if (close(fd) != 0)
		die(-1, "Cannot close");
}

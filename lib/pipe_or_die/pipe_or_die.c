#include <unistd.h>

#include <fsyscall/private/die.h>

void
pipe_or_die(int fds[2])
{
	if (pipe(fds) != 0)
		die(-1, "Cannot pipe");
}

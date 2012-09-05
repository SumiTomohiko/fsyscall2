#include <err.h>
#include <unistd.h>

void
pipe_or_die(int fds[2])
{
	if (pipe(fds) != 0)
		err(-1, "Cannot pipe");
}

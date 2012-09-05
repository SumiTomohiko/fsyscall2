#include <sys/types.h>
#include <err.h>
#include <unistd.h>

pid_t
fork_or_die()
{
	pid_t pid = fork();
	if (pid == -1)
		err(-1, "Cannot fork");
	return (pid);
}

#include <sys/types.h>
#include <unistd.h>

#include <fsyscall/private/die.h>

pid_t
fork_or_die()
{
	pid_t pid = fork();
	if (pid == -1)
		die(-1, "cannot fork");
	return (pid);
}

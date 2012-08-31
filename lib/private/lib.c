#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void
pipe_or_die(int fds[2])
{
	if (pipe(fds) != 0) {
		err(-1, "Cannot pipe");
	}
}

void
close_or_die(int fd)
{
	if (close(fd) != 0) {
		err(-1, "Cannot close");
	}
}

pid_t
fork_or_die()
{
	pid_t pid = fork();
	if (pid == -1) {
		err(-1, "Cannot fork");
	}
	return (pid);
}

void
waitpid_or_die(pid_t pid, int *status)
{
	if (waitpid(pid, status, 0) == -1) {
		err(-1, "Cannot waitpid %d", pid);
	}
}

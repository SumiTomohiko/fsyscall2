#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
atoi_or_die(const char *s, const char *name)
{
	char *endptr;
	int base = 10;
	int n = strtol(s, &endptr, base);

	if (*endptr != '\0') {
		printf("%s must be an integer.\n", name);
		exit(-1);
	}
	return (n);
}

void
write_or_die(int fd, const void *buf, size_t nbytes)
{
	size_t n = 0;
	ssize_t m;

	while (n < nbytes) {
		m = write(fd, (char *)buf + n, nbytes - n);
		if (m < 0)
			err(-1, "Cannot write");
		n -= m;
	}
}

void
read_or_die(int fd, const void *buf, size_t nbytes)
{
	size_t n = 0;
	ssize_t m;

	while (n < nbytes) {
		m = read(fd, (char *)buf + n, nbytes - n);
		if (m == 0)
			errc(-1, EBADF, "End-of-file reached");
		if (m < 0)
			err(-1, "Cannot read");
		n -= m;
	}
}

void
pipe_or_die(int fds[2])
{
	if (pipe(fds) != 0)
		err(-1, "Cannot pipe");
}

void
close_or_die(int fd)
{
	if (close(fd) != 0)
		err(-1, "Cannot close");
}

pid_t
fork_or_die()
{
	pid_t pid = fork();
	if (pid == -1)
		err(-1, "Cannot fork");
	return (pid);
}

void
waitpid_or_die(pid_t pid, int *status)
{
	if (waitpid(pid, status, 0) == -1)
		err(-1, "Cannot waitpid %d", pid);
}

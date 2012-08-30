#include <err.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void
close_or_die(int fd)
{
	if (close(fd) != 0) {
		err(-1, "Cannot close");
	}
}

static pid_t
fork_or_die()
{
	pid_t pid = fork();
	if (pid == -1) {
		err(-1, "Cannot fork");
	}
	return (pid);
}

static void
pipe_or_die(int fds[2])
{
	if (pipe(fds) != 0) {
		err(-1, "Cannot pipe");
	}
}

#define	R	0
#define	W	1

static void
start_master(int shub2mhub, int mhub2shub)
{
	/* TODO */
}

static int
dup_or_die(int old_fd)
{
	int new_fd = dup(old_fd);
	if (new_fd == -1) {
		err(-1, "Cannot dup");
	}
	return old_fd;
}

static int
dup_to_nonstd(int fd)
{
	char *path = "/dev/null";
	int new_fd, tmp, tmp2;

	if ((fd != 0) && (fd != 1) && (fd != 2)) {
		return fd;
	}

	tmp = open(path, O_RDONLY);
	tmp2 = open(path, O_RDONLY);
	new_fd = dup_or_die(fd);
	close_or_die(fd);
	close_or_die(tmp2);
	close_or_die(tmp);

	return new_fd;
}

static void
start_slave(int mhub2shub, int shub2mhub)
{
	char args[6][8], *file = args[0], path[32];
	int slave2hub[2], hub2slave[2];
	int len, rfd, wfd;
	pid_t pid;

	snprintf(path, sizeof(path), "/tmp/fshub.%d", getpid());

	pipe_or_die(slave2hub);
	pipe_or_die(hub2slave);

	pid = fork_or_die();
	if (pid == 0) {
		close_or_die(slave2hub[W]);
		close_or_die(hub2slave[R]);

		strcpy(args[0], "fshub");
		sprintf(args[1], "%d", mhub2shub);
		sprintf(args[2], "%d", shub2mhub);
		sprintf(args[3], "%d", slave2hub[R]);
		sprintf(args[4], "%d", hub2slave[W]);
		execlp(
			file,
			args[0], args[1], args[2], args[3], args[4], path,
			NULL);
		err(-1, "Cannot execlp %s", file);
		/* NOTREACHED */
	}
	close_or_die(mhub2shub);
	close_or_die(shub2mhub);
	close_or_die(hub2slave[W]);
	close_or_die(slave2hub[R]);
	rfd = dup_to_nonstd(hub2slave[R]);
	wfd = dup_to_nonstd(slave2hub[W]);
	strcpy(args[0], "fslave");
	sprintf(args[1], "%d", rfd);
	sprintf(args[2], "%d", wfd);
	execlp(file, args[0], args[1], args[2], path, NULL);
	err(-1, "Cannot execlp %s", file);
	/* NOTREACHED */
}

static void
waitpid_or_die(pid_t pid, int *status)
{
	if (waitpid(pid, status, 0) == -1) {
		err(-1, "Cannot waitpid %d", pid);
	}
}

static bool
status_is_fail(int status)
{
	return (!WIFEXITED(status) || (WEXITSTATUS(status) != 0));
}

int
main(int argc, const char *argv[])
{
	int master_status, slave_status;
	int mhub2shub[2], shub2mhub[2];
	pid_t master_pid, slave_pid;

	pipe_or_die(shub2mhub);
	pipe_or_die(mhub2shub);

	slave_pid = fork_or_die();
	if (slave_pid == 0) {
		close_or_die(shub2mhub[R]);
		close_or_die(mhub2shub[W]);
		start_slave(mhub2shub[R], shub2mhub[W]);
		/* NOTREACHED */
	}

	master_pid = fork_or_die();
	if (master_pid == 0) {
		close_or_die(mhub2shub[R]);
		close_or_die(shub2mhub[W]);
		start_master(shub2mhub[R], mhub2shub[W]);
		/* NOTREACHED */
	}

	waitpid_or_die(slave_pid, &slave_status);
	waitpid_or_die(master_pid, &master_status);

	if (status_is_fail(slave_status) || status_is_fail(master_status)) {
		return (-1);
	}

	return (0);
}

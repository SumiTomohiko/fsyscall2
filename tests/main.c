#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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

#define	ALLOC_FD(x, fd)	do {			\
	x = (char*)alloca(sizeof(char) * 16);	\
	sprintf(x, "%d", (fd));			\
} while (0)

static void
start_master(int shub2mhub, int mhub2shub, int argc, char* argv[])
{
	int i;
	char **args;

	args = (char**)alloca(sizeof(char*) * (argc + 4));
	args[0] = "fmaster";
	ALLOC_FD(args[1], shub2mhub);
	ALLOC_FD(args[2], mhub2shub);
	for (i = 0; i < argc; i++) {
		args[3 + i] = argv[i];
	}
	args[i] = NULL;

	execvp(args[0], args);
	err(-1, "Cannot execvp %s", args[0]);
	/* NOTREACHED */
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
	int new_fd, tmp, tmp2;
	char *path = "/dev/null";

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
exec_fshub(int mhub2shub, int shub2mhub, int slave2hub, int hub2slave, char *path, int argc, char *argv[])
{
	int i;
	char **args;

	args = (char**)alloca(sizeof(char*) * (7 + argc));
	args[0] = "fshub";
	ALLOC_FD(args[1], mhub2shub);
	ALLOC_FD(args[2], shub2mhub);
	ALLOC_FD(args[3], slave2hub);
	ALLOC_FD(args[4], hub2slave);
	args[5] = path;
	for (i = 0; i < argc; i++) {
		args[6 + i] = argv[i];
	}
	args[i] = NULL;
	execvp(args[0], args);
	err(-1, "Cannot execvp %s", args[0]);
	/* NOTREACHED */
}

static void
start_slave(int mhub2shub, int shub2mhub, int argc, char *argv[])
{
	pid_t pid;
	int slave2hub[2], hub2slave[2];
	int len, rfd, wfd;
	char **args, path[32];

	snprintf(path, sizeof(path), "/tmp/fshub.%d", getpid());

	pipe_or_die(slave2hub);
	pipe_or_die(hub2slave);

	pid = fork_or_die();
	if (pid == 0) {
		close_or_die(slave2hub[W]);
		close_or_die(hub2slave[R]);
		exec_fshub(
			mhub2shub, shub2mhub,
			slave2hub[R], hub2slave[W],
			path,
			argc, argv);
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
	execlp(args[0], args[0], args[1], args[2], path, NULL);
	err(-1, "Cannot execlp %s", args[0]);
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
main(int argc, char *argv[])
{
	pid_t master_pid, slave_pid;
	int i, master_status, slave_status;
	int mhub2shub[2], shub2mhub[2];
	char **args;

	assert(1 < argc);
	args = (char**)alloca(sizeof(char*) * (argc - 1));
	for (i = 1; i < argc; i++) {
		args[i - 1] = argv[i];
	}

	pipe_or_die(shub2mhub);
	pipe_or_die(mhub2shub);

	slave_pid = fork_or_die();
	if (slave_pid == 0) {
		close_or_die(shub2mhub[R]);
		close_or_die(mhub2shub[W]);
		start_slave(mhub2shub[R], shub2mhub[W], argc - 1, args);
		/* NOTREACHED */
	}

	master_pid = fork_or_die();
	if (master_pid == 0) {
		close_or_die(mhub2shub[R]);
		close_or_die(shub2mhub[W]);
		start_master(shub2mhub[R], mhub2shub[W], argc - 1, args);
		/* NOTREACHED */
	}

	waitpid_or_die(slave_pid, &slave_status);
	waitpid_or_die(master_pid, &master_status);

	if (status_is_fail(slave_status) || status_is_fail(master_status)) {
		return (-1);
	}

	return (0);
}

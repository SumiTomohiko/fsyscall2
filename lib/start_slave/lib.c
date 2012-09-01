#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fsyscall/private.h>

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
	args[6 + i] = NULL;
	execvp(args[0], args);
	err(-1, "Cannot execvp %s", args[0]);
	/* NOTREACHED */
}

void
fsyscall_start_slave(int mhub2shub, int shub2mhub, int argc, char *argv[])
{
	pid_t pid;
	int slave2hub[2], hub2slave[2];
	int len, rfd, wfd;
	char args[3][16], path[32];

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

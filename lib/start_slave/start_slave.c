#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fsyscall.h>
#include <fsyscall/private/close_or_die.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/fork_or_die.h>
#include <fsyscall/private/pipe_or_die.h>
#include <fsyscall/private/start.h>

static int
dup_or_die(int old_fd)
{
	int new_fd = dup(old_fd);
	if (new_fd == -1)
		die(-1, "cannot dup");
	return (old_fd);
}

static int
dup_to_nonstd(int fd)
{
	int new_fd, tmp, tmp2;
	char *path = "/dev/null";

	if ((fd != 0) && (fd != 1) && (fd != 2))
		return (fd);

	tmp = open(path, O_RDONLY);
	tmp2 = open(path, O_RDONLY);
	new_fd = dup_or_die(fd);
	close_or_die(fd);
	close_or_die(tmp2);
	close_or_die(tmp);

	return (new_fd);
}

static void
exec_fshub(int mhub2shub, int shub2mhub, int slave2hub, int hub2slave, char *path)
{
	char **args;

	args = (char **)alloca(sizeof(char *) * 7);
	args[0] = "fshub";
	ALLOC_FD(args[1], mhub2shub);
	ALLOC_FD(args[2], shub2mhub);
	ALLOC_FD(args[3], slave2hub);
	ALLOC_FD(args[4], hub2slave);
	args[5] = path;
	args[6] = NULL;
	execvp(args[0], args);
	die(-1, "cannot execvp %s", args[0]);
	/* NOTREACHED */
}

void
fsyscall_start_slave(int mhub2shub, int shub2mhub, int argc, char *argv[])
{
	pid_t pid;
	int slave2hub[2], hub2slave[2];
	int digits, i;
	char **args, *cmd, path[32], *verbose;

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
			path);
		/* NOTREACHED */
	}

	verbose = getenv(FSYSCALL_ENV_VERBOSE);
	if ((verbose != NULL) && (strcmp(verbose, "1") == 0))
		printf("pid of fshub=%d\n", pid);

	close_or_die(mhub2shub);
	close_or_die(shub2mhub);
	close_or_die(hub2slave[W]);
	close_or_die(slave2hub[R]);

	args = (char **)alloca(sizeof(char *) * (5 + argc));
	cmd = "fslave";
	args[0] = (char *)alloca(sizeof(char) * (strlen(cmd) + 1));
	strcpy(args[0], cmd);
	digits = 11;
	args[1] = (char *)alloca(sizeof(char) * digits);
	snprintf(args[1], digits, "%d", dup_to_nonstd(hub2slave[R]));
	args[2] = (char *)alloca(sizeof(char) * digits);
	snprintf(args[2], digits, "%d", dup_to_nonstd(slave2hub[W]));
	args[3] = (char *)alloca(sizeof(char) * (strlen(path) + 1));
	strcpy(args[3], path);
	for (i = 0; i < argc; i++)
		args[4 + i] = argv[i];
	args[4 + i] = NULL;

	execvp(args[0], args);
	die(-1, "cannot execlp %s", args[0]);
	/* NOTREACHED */
}

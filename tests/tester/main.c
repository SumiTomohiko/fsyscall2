#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

#include <fsyscall/private.h>
#include <fsyscall/private/close_or_die.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/fork_or_die.h>
#include <fsyscall/private/pipe_or_die.h>
#include <fsyscall/start_master.h>
#include <fsyscall/start_slave.h>

static void
waitpid_or_die(pid_t pid, int *status)
{
	if (waitpid(pid, status, 0) == -1)
		die(-1, "Cannot waitpid %d", pid);
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
	int i, master_status, r, slave_status, w;
	int mhub2shub[2], shub2mhub[2];
	char **args;

	assert(1 < argc);
	args = (char**)alloca(sizeof(char*) * (argc - 1));
	for (i = 1; i < argc; i++)
		args[i - 1] = argv[i];

	pipe_or_die(shub2mhub);
	pipe_or_die(mhub2shub);

	slave_pid = fork_or_die();
	if (slave_pid == 0) {
		close_or_die(shub2mhub[R]);
		close_or_die(mhub2shub[W]);
		r = mhub2shub[R];
		w = shub2mhub[W];
		fsyscall_start_slave(r, w, argc - 1, args);
		/* NOTREACHED */
	}

	master_pid = fork_or_die();
	if (master_pid == 0) {
		close_or_die(mhub2shub[R]);
		close_or_die(shub2mhub[W]);
		r = shub2mhub[R];
		w = mhub2shub[W];
		fsyscall_start_master(r, w, argc - 1, args);
		/* NOTREACHED */
	}

	waitpid_or_die(slave_pid, &slave_status);
	waitpid_or_die(master_pid, &master_status);
	if (!WIFEXITED(slave_status) || !WIFEXITED(master_status))
		return (-1);

	return (WEXITSTATUS(slave_status));
}

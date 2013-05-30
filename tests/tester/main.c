#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <fsyscall.h>
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
		die(-1, "cannot waitpid %d", pid);
}

static bool
status_is_fail(int status)
{
	return (!WIFEXITED(status) || (WEXITSTATUS(status) != 0));
}

static void
usage()
{
	puts("tester [--java] [-v|--verbose] commands...");
}

static void
start_java_slave(int rfd, int wfd, int _, char *__[])
{
	char *argv[7], rbuf[32], wbuf[32];

	snprintf(rbuf, sizeof(rbuf), "%d", rfd);
	snprintf(wbuf, sizeof(wbuf), "%d", wfd);
	argv[0] = "java";
	argv[1] = "-classpath";
	argv[2] = "java/bin/fsyscall.slave.jar";
	argv[3] = "jp.gr.java_conf.neko_daisuki.fsyscall.slave.Application";
	argv[4] = rbuf;
	argv[5] = wbuf;
	argv[6] = NULL;
	execvp(argv[0], argv);
	die(1, "failed to execvp");
}

int
main(int argc, char *argv[])
{
	struct option long_opts[] = {
		{ "java", no_argument, NULL, 'j' },
		{ "verbose", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	pid_t master_pid, slave_pid;
	void (*start_slave)(int, int, int, char *[]);
	int i, opt, master_status, r, slave_status, w;
	int mhub2shub[2], shub2mhub[2];
	bool java = false, verbose = false;
	char **args, *fmt;

	while ((opt = getopt_long(argc, argv, "v", long_opts, NULL)) != -1)
		switch (opt) {
		case 'j':
			java = true;
			break;
		case 'v':
			setenv(FSYSCALL_ENV_VERBOSE, "1", 1);
			verbose = true;
			break;
		case '?':
		default:
			usage();
			return (1);
		}
	argc -= optind;
	argv += optind;

	pipe_or_die(shub2mhub);
	pipe_or_die(mhub2shub);

	slave_pid = fork_or_die();
	if (slave_pid == 0) {
		close_or_die(shub2mhub[R]);
		close_or_die(mhub2shub[W]);
		r = mhub2shub[R];
		w = shub2mhub[W];
		start_slave = !java ? fsyscall_start_slave : start_java_slave;
		start_slave(r, w, argc, argv);
		/* NOTREACHED */
	}

	master_pid = fork_or_die();
	if (master_pid == 0) {
		close_or_die(mhub2shub[R]);
		close_or_die(shub2mhub[W]);
		r = shub2mhub[R];
		w = mhub2shub[W];
		fsyscall_start_master(r, w, argc, argv);
		/* NOTREACHED */
	}

	if (verbose) {
		printf("pid of fmhub=%d\n", master_pid);
		printf("pid of fslave=%d\n", slave_pid);
	}

	close_or_die(shub2mhub[R]);
	close_or_die(shub2mhub[W]);
	close_or_die(mhub2shub[R]);
	close_or_die(mhub2shub[W]);
	waitpid_or_die(slave_pid, &slave_status);
	waitpid_or_die(master_pid, &master_status);
	if (!WIFEXITED(slave_status) || !WIFEXITED(master_status))
		return (-1);

	return (WEXITSTATUS(slave_status));
}

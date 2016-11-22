#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <fsyscall.h>
#include <fsyscall/private.h>
#include <fsyscall/private/close_or_die.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/fork_or_die.h>
#include <fsyscall/private/pipe_or_die.h>
#include <fsyscall/run_master.h>
#include <fsyscall/start_slave.h>

#define	STATUS_TIMEOUT	255

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
	puts("tester [-v|--verbose] commands...");
}

static int sigfd;

static void
signal_handler(int sig)
{
	size_t size;
	char c;

	c = 0;
	size = sizeof(c);
	if (write(sigfd, &c, size) != size)
		die(1, "cannot write(2) to signal pipe");
}

static void
initialize_signal_handler()
{
	struct sigaction act;

	act.sa_handler = signal_handler;
	act.sa_flags = 0;
	if (sigfillset(&act.sa_mask) == -1)
		die(1, "sigfillset(3) failed");
	if (sigaction(SIGCHLD, &act, NULL) == -1)
		die(1, "sigaction(2) for SIGCHLD failed");
}

static int
wait_sigchld(int fd)
{
	fd_set fds;
	struct timeval timeout;
	size_t size;
	int i, n;
	char c;

	timeout.tv_sec = 60;
	timeout.tv_usec = 0;
	i = 0;
	while (i < 2) {
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		n = select(fd + 1, &fds, NULL, NULL, &timeout);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			die(1, "select(2) for fd %d failed", fd);
		}
		if (n == 0)
			die_with_message(STATUS_TIMEOUT, "timeout");
		size = sizeof(c);
		if (read(fd, &c, size) != size)
			die(1, "read(2) for fd %d failed", fd);
		i++;
	}

	return (0);
}

int
main(int argc, char *argv[])
{
	struct option long_opts[] = {
		{ "verbose", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	pid_t master_pid, pid, pids[2], slave_pid;
	int i, opt, master_status, r, sigfds[2], slave_status, w;
	int mhub2shub[2], shub2mhub[2];
	bool verbose = false;
	char **args, *fmt;

	while ((opt = getopt_long(argc, argv, "v", long_opts, NULL)) != -1)
		switch (opt) {
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

	pipe_or_die(sigfds);
	initialize_signal_handler();
	sigfd = sigfds[W];

	slave_pid = fork_or_die();
	if (slave_pid == 0) {
		close_or_die(shub2mhub[R]);
		close_or_die(mhub2shub[W]);
		close_or_die(sigfds[R]);
		close_or_die(sigfds[W]);
		r = mhub2shub[R];
		w = shub2mhub[W];
		fsyscall_start_slave(r, w, argc, argv);
		/* NOTREACHED */
	}

	master_pid = fork_or_die();
	if (master_pid == 0) {
		close_or_die(mhub2shub[R]);
		close_or_die(shub2mhub[W]);
		close_or_die(sigfds[R]);
		close_or_die(sigfds[W]);
		r = shub2mhub[R];
		w = mhub2shub[W];
		/*
		 * The man page of environ(7) does not tell which header
		 * includes the declaration of environ. I found it in
		 * /usr/include/roken.h, but it seems unused. Because
		 * /usr/src/lib/libc/gen/exec.c does not include this header.
		 * exec.c declares extern environ by itself.
		 */
		extern char *const *environ;
		return (fsyscall_run_master(r, w, argc, argv, environ));
	}

	if (verbose) {
		printf("pid of fmhub=%d\n", master_pid);
		printf("pid of fslave=%d\n", slave_pid);
	}

	close_or_die(shub2mhub[R]);
	close_or_die(shub2mhub[W]);
	close_or_die(mhub2shub[R]);
	close_or_die(mhub2shub[W]);
	if (wait_sigchld(sigfds[R]) != 0) {
		pids[0] = slave_pid;
		pids[1] = master_pid;
		for (i = 0; i < sizeof(pids) / sizeof(pids[0]); i++) {
			pid = pids[i];
			if (kill(pid, SIGKILL) == -1)
				warn("no such process: %d", pid);
		}
	}
	waitpid_or_die(slave_pid, &slave_status);
	waitpid_or_die(master_pid, &master_status);
	if (!WIFEXITED(slave_status) || !WIFEXITED(master_status))
		return (-1);

	return (WEXITSTATUS(slave_status));
}

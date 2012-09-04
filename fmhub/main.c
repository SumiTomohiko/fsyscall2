#include <sys/types.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <fsyscall/private.h>

struct master {
	struct master *prev;
	struct master *next;
	int rfd;
	int wfd;
};

struct mhub {
	struct connection shub;

	/* The first one and the last one are sentinels. */
	struct master *masters;
};

static void
usage()
{
	puts("fmhub rfd wfd command...");
}

static void
prepend_master(struct mhub *mhub, struct master *master)
{
	struct master *head = mhub->masters;

	master->next = head->next;
	master->prev = head;
	head->next->prev = master;
	head->next = master;
}

static void
negotiate_version_with_master(struct master *master)
{
	uint8_t request, ver = 0;

	read_or_die(master->rfd, &request, sizeof(request));
	assert(request == 0);
	write_or_die(master->wfd, &ver, sizeof(ver));
	syslog(LOG_INFO, "Protocol version for master is %d.", ver);
}

static void
negotiate_version_with_shub(struct mhub *mhub)
{
	uint8_t request;
	uint8_t ver = 0;

	read_or_die(mhub->shub.rfd, &request, sizeof(request));
	assert(request == 0);
	write_or_die(mhub->shub.wfd, &ver, sizeof(ver));
	syslog(LOG_INFO, "Protocol version for shub is %d.", ver);
}

static int
find_syscall()
{
	struct module_stat stat;
	int modid;
	const char *modname = "sys/fmaster";

	modid = modfind(modname);
	if (modid == -1)
		err(-1, "Cannot modfind %s", modname);

	stat.version = sizeof(stat);
	if (modstat(modid, &stat) != 0)
		err(-1, "Cannot modstat %s", modname);

	return (stat.data.intval);
}

static void
exec_master(int syscall_num, int rfd, int wfd, int argc, char *argv[])
{
	char **args, *envp[] = { NULL };
	int i;

	args = (char **)alloca(sizeof(char *) * (argc + 1));
	for (i = 0; i < argc; i++) {
		args[i] = (char *)alloca(sizeof(char) * strlen(argv[i]) + 1);
		strcpy(args[i], argv[i]);
	}
	args[i] = NULL;

	syscall(syscall_num, rfd, wfd, args[0], args, envp);
	err(1, "fmaster_evecve failed");
	/* NOTREACHED */
}

static int
mhub_main(struct mhub *mhub, int argc, char *argv[])
{
	struct master *master;
	int hub2master[2], master2hub[2], rfd, syscall_num, wfd;
	pid_t pid;

	syscall_num = find_syscall();

	pipe_or_die(hub2master);
	pipe_or_die(master2hub);

	pid = fork_or_die();
	if (pid == 0) {
		close_or_die(hub2master[W]);
		close_or_die(master2hub[R]);

		rfd = hub2master[R];
		wfd = master2hub[W];
		exec_master(syscall_num, rfd, wfd, argc, argv);
		/* NOTREACHED */
	}

	close_or_die(hub2master[R]);
	close_or_die(master2hub[W]);

	master = malloc_or_die(sizeof(*master));
	master->rfd = master2hub[R];
	master->wfd = hub2master[W];
	prepend_master(mhub, master);

	negotiate_version_with_shub(mhub);
	negotiate_version_with_master(master);

	/* TODO: Free masters. */

	return (0);
}

int
main(int argc, char *argv[])
{
	struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	struct mhub mhub;
	struct master head, tail;
	int opt;
	char **args;

	openlog(argv[0], LOG_PID, LOG_USER);

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1)
		switch (opt) {
		case 'h':
			usage();
			return (0);
		case 'v':
			puts("fmhub 0.42.0");
			return (0);
		default:
			usage();
			return (-1);
		}
	if (argc - optind < 3) {
		usage();
		return (-1);
	}

	args = &argv[optind];
	mhub.shub.rfd = atoi_or_die(args[0], "rfd");
	mhub.shub.wfd = atoi_or_die(args[1], "wfd");

	head.rfd = head.wfd = tail.rfd = tail.wfd = -1;
	head.prev = NULL;
	head.next = &tail;
	tail.prev = &head;
	tail.next = NULL;
	mhub.masters = &head;

	return (mhub_main(&mhub, argc - optind - 2, args + 2));
}

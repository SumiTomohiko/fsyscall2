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

struct mhub {
	int rfd;
	int wfd;
};

static void
usage()
{
	puts("fmhub rfd wfd command...");
}

static void
negotiate_version_with_shub(struct mhub *mhub)
{
	uint8_t request;
	uint8_t ver = 0;

	read_or_die(mhub->rfd, &request, sizeof(request));
	assert(request == 0);
	write_or_die(mhub->wfd, &ver, sizeof(ver));
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

	negotiate_version_with_shub(mhub);

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
	mhub.rfd = atoi_or_die(args[0], "rfd");
	mhub.wfd = atoi_or_die(args[1], "wfd");

	return (mhub_main(&mhub, argc - optind - 2, args + 2));
}

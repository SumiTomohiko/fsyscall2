#include <sys/types.h>
#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <syslog.h>

#include <fsyscall.h>
#include <fsyscall/private.h>
#include <fsyscall/private/atoi_or_die.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/hub.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/list.h>
#include <fsyscall/private/malloc_or_die.h>

struct slave {
	struct item item;
	int rfd;
	int wfd;
	pid_t pid;
	pid_t master_pid;
};

struct shub {
	struct connection mhub;
	struct list slaves;
	const char *path;
};

static void
usage()
{
	puts("fshub mhub_rfd mhub_wfd slave_rfd slave_wfd path");
}

static void
negotiate_version_with_mhub(struct shub *shub)
{
	uint8_t request;
	uint8_t ver = 0;

	write_or_die(shub->mhub.wfd, &ver, sizeof(ver));
	read_or_die(shub->mhub.rfd, &request, sizeof(request));
	assert(request == 0);
	syslog(LOG_INFO, "Protocol version for mhub is %d.", ver);
}

static void
negotiate_version_with_slave(struct slave *slave)
{
	uint8_t request, ver = 0;

	read_or_die(slave->rfd, &request, sizeof(request));
	assert(request == 0);
	write_or_die(slave->wfd, &ver, sizeof(ver));
	syslog(LOG_INFO, "Protocol version for slave is %d.", ver);
}

static void
read_pids(struct shub *shub, struct slave *slave)
{
	slave->pid = read_pid(slave->rfd);
	slave->master_pid = read_pid(shub->mhub.rfd);
}

static int
shub_main(struct shub *shub)
{
	struct slave *slave = (struct slave *)FIRST_ITEM(&shub->slaves);

	negotiate_version_with_mhub(shub);
	negotiate_version_with_slave(slave);
	read_pids(shub, slave);
	transport_fds(slave->rfd, shub->mhub.wfd);

	return (0);
}

static void
signal_handler(int sig)
{
	assert(sig == SIGPIPE);
	diex(-1, "Signaled SIGPIPE.");
	/* NOTREACHED */
}

int
main(int argc, char *argv[])
{
	struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	struct shub shub;
	int opt;
	char **args;

	openlog(argv[0], LOG_PID, LOG_USER);
	syslog(LOG_INFO, "Started.");

	signal(SIGPIPE, signal_handler);

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1)
		switch (opt) {
		case 'h':
			usage();
			return (0);
		case 'v':
			printf("fshub %s\n", FSYSCALL_VERSION);
			return (0);
		default:
			usage();
			return (-1);
		}
	if (argc - optind < 5) {
		usage();
		return (-1);
	}

	args = &argv[optind];
	shub.mhub.rfd = atoi_or_die(args[0], "mhub_rfd");
	shub.mhub.wfd = atoi_or_die(args[1], "mhub_wfd");

	initialize_list(&shub.slaves);
	struct slave *slave = (struct slave *)malloc_or_die(sizeof(*slave));
	slave->rfd = atoi_or_die(args[2], "slave_rfd");
	slave->wfd = atoi_or_die(args[3], "slave_wfd");
	PREPEND_ITEM(&shub.slaves, slave);

	shub.path = args[4];

	return (shub_main(&shub));
}

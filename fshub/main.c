#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <syslog.h>

#include <fsyscall/private.h>
#include <fsyscall/private/atoi_or_die.h>
#include <fsyscall/private/hub.h>
#include <fsyscall/private/io.h>

struct shub {
	struct connection mhub;
	struct connection slave;
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
negotiate_version_with_slave(struct shub *shub)
{
	uint8_t request;
	uint8_t ver = 0;

	read_or_die(shub->slave.rfd, &request, sizeof(request));
	assert(request == 0);
	write_or_die(shub->slave.wfd, &ver, sizeof(ver));
	syslog(LOG_INFO, "Protocol version for slave is %d.", ver);
}

static int
shub_main(struct shub *shub)
{
	negotiate_version_with_mhub(shub);
	negotiate_version_with_slave(shub);

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
	struct shub shub;
	int opt;
	char **args;

	openlog(argv[0], LOG_PID, LOG_USER);

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1)
		switch (opt) {
		case 'h':
			usage();
			return (0);
		case 'v':
			puts("fshub 0.42.0");
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
	shub.slave.rfd = atoi_or_die(args[2], "slave_rfd");
	shub.slave.wfd = atoi_or_die(args[3], "slave_wfd");
	shub.path = args[4];

	return (shub_main(&shub));
}

#include <sys/types.h>
#include <sys/uio.h>
#include <assert.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fsyscall/private.h>

struct slave {
	int rfd;
	int wfd;
	const char *path;
};

static void
usage()
{
	puts("fslave rfd wfd path");
}

static void
negotiate_version(struct slave *slave)
{
	uint8_t request_ver = 0;
	uint8_t response;

	write_or_die(slave->wfd, &request_ver, sizeof(request_ver));
	read_or_die(slave->rfd, &response, sizeof(response));
	assert(response == 0);
}

static int
slave_main(struct slave *slave)
{
	negotiate_version(slave);
	return (0);
}

int
main(int argc, char* argv[])
{
	struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	struct slave slave;
	int opt;
	char **args;

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return (0);
		case 'v':
			puts("fslave 0.42.0");
			return (0);
		default:
			usage();
			return (-1);
		}
	}
	if (argc - optind != 3) {
		usage();
		return (-1);
	}

	args = &argv[optind];
	slave.rfd = atoi_or_die(args[0], "rfd");
	slave.wfd = atoi_or_die(args[1], "wfd");
	slave.path = args[2];

	return (slave_main(&slave));
}

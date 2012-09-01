#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <syslog.h>

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
mhub_main(struct mhub *mhub, int argc, char *argv[])
{
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

	return (mhub_main(&mhub, argc - optind, args));
}

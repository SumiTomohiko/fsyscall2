#include <sys/types.h>
#include <sys/uio.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include <fsyscall/encode.h>
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
	syslog(LOG_INFO, "Protocol version for shub is %d.", response);
}

static bool
is_alive_fd(int fd)
{
	if (fcntl(fd, F_GETFL) != -1)
		return (true);
	if (errno != EBADF)
		err(-1, "Cannot fcntl(%d, F_GETFL)", fd);
	return (false);
}

static int
count_alive_fds()
{
	int i, n = 0, size;

	size = getdtablesize();
	for (i = 0; i < size; i++)
		n += is_alive_fd(i) ? 1 : 0;

	return (n);
}

static int
encode_alive_fd(int fd, char *dest, int size)
{
	return (is_alive_fd(fd) ? fsyscall_encode_int(fd, dest, size) : 0);
}

static void
send_open_fds(struct slave *slave)
{
	size_t buf_size;
	int i, nfds, pos, wfd;
	char *buf;

	buf_size = sizeof(char) * count_alive_fds() * FSYSCALL_BUFSIZE_INT;
	buf = (char *)alloca(buf_size);

	pos = 0;
	nfds = getdtablesize();
	for (i = 0; i < nfds; i++)
		pos += encode_alive_fd(i, buf + pos, buf_size - pos);

	assert(0 <= pos);
	wfd = slave->wfd;
	send_int(wfd, pos);
	write_or_die(wfd, buf, pos);
}

static int
slave_main(struct slave *slave)
{
	negotiate_version(slave);
	send_open_fds(slave);

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

	openlog(argv[0], LOG_PID, LOG_USER);

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != -1)
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

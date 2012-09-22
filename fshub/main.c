#include <sys/param.h>
#include <sys/select.h>
#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <syslog.h>

#include <fsyscall.h>
#include <fsyscall/private.h>
#include <fsyscall/private/atoi_or_die.h>
#include <fsyscall/private/close_or_die.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/hub.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/list.h>
#include <fsyscall/private/log.h>
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

static struct slave *
find_slave_of_rfd(struct shub *shub, int rfd)
{
	struct slave *slave;

	slave = (struct slave *)FIRST_ITEM(&shub->slaves);
	while ((ITEM_NEXT(slave) != NULL) && (slave->rfd != rfd))
		slave = (struct slave *)ITEM_NEXT(slave);
	assert(ITEM_NEXT(slave) != NULL);

	return (slave);
}

static struct slave *
find_slave_of_master_pid(struct shub *shub, pid_t master_pid)
{
	struct slave *slave;

	slave = (struct slave *)FIRST_ITEM(&shub->slaves);
	while ((ITEM_NEXT(slave) != NULL) && (slave->master_pid != master_pid))
		slave = (struct slave *)ITEM_NEXT(slave);
	assert(ITEM_NEXT(slave) != NULL);

	return (slave);
}

static void
dispose_slave(struct slave *slave)
{
	REMOVE_ITEM(slave);
	close_or_die(slave->rfd);
	close_or_die(slave->wfd);
	free(slave);
}

static void
transfer_payload_to_slave(struct shub *shub, command_t cmd)
{
	pid_t pid;
	uint32_t payload_size;
	int len, rfd, wfd;
	char buf[FSYSCALL_BUFSIZE_INT32];
	const char *name;
	const char *fmt = "%s: master_pid=%d, payload_size=%u";

	name = get_command_name(cmd);
	syslog(LOG_DEBUG, "Processing %s.", name);

	rfd = shub->mhub.rfd;
	pid = read_pid(rfd);
	len = read_numeric_sequence(rfd, buf, array_sizeof(buf));
	payload_size = fsyscall_decode_uint32(buf, len);

	syslog(LOG_DEBUG, fmt, name, pid, payload_size);

	wfd = find_slave_of_master_pid(shub, pid)->wfd;
	write_command(wfd, cmd);
	write_or_die(wfd, buf, len);
	transfer(rfd, wfd, payload_size);
}

static void
process_exit(struct shub *shub)
{
	struct slave *slave;
	pid_t pid;
	int rfd, status, wfd;

	rfd = shub->mhub.rfd;
	pid = read_pid(rfd);
	slave = find_slave_of_master_pid(shub, pid);
	status = read_int32(rfd);
	syslog(LOG_DEBUG, "CALL_EXIT: master_pid=%d, status=%d", pid, status);

	wfd = slave->wfd;
	write_command(wfd, CALL_EXIT);
	write_int32(wfd, status);

	dispose_slave(slave);
}

static void
process_mhub(struct shub *shub)
{
	command_t cmd;

	cmd = read_command(shub->mhub.rfd);
	switch (cmd) {
	case CALL_EXIT:
		process_exit(shub);
		break;
	case CALL_CLOSE:
	case CALL_OPEN:
	case CALL_WRITE:
		transfer_payload_to_slave(shub, cmd);
		break;
	default:
		diex(-1, "Unknown command (%d) from the master hub", cmd);
		/* NOTREACHED */
	}
}

static void
transfer_payload_from_slave(struct shub *shub, struct slave *slave, command_t cmd)
{
	uint32_t payload_size;
	int len, rfd, wfd;
	char buf[FSYSCALL_BUFSIZE_UINT32];
	const char *name;

	name = get_command_name(cmd);
	syslog(LOG_DEBUG, "Processing %s.", name);

	rfd = slave->rfd;
	len = read_numeric_sequence(rfd, buf, array_sizeof(buf));
	payload_size = fsyscall_decode_uint32(buf, len);

	syslog(LOG_DEBUG, "%s: payload_size=%u", name, payload_size);

	wfd = shub->mhub.wfd;
	write_command(wfd, cmd);
	write_pid(wfd, slave->master_pid);
	write_or_die(wfd, buf, len);
	transfer(rfd, wfd, payload_size);
}

static void
process_slave(struct shub *shub, struct slave *slave)
{
	command_t cmd;

	cmd = read_command(slave->rfd);
	switch (cmd) {
	case RET_CLOSE:
	case RET_OPEN:
	case RET_WRITE:
		transfer_payload_from_slave(shub, slave, cmd);
		break;
	default:
		diex(-1, "Unknown command (%d) from slave %d", cmd, slave->pid);
	}
}

static void
process_fd(struct shub *shub, int fd, fd_set *fds)
{
	/*
	 * TODO: This part is almost same as fmhub/main.c (process_fd). Share
	 * code with it.
	 */
	struct slave *slave;

	if (!FD_ISSET(fd, fds))
		return;
	if (shub->mhub.rfd == fd) {
		process_mhub(shub);
		return;
	}

	slave = find_slave_of_rfd(shub, fd);
	process_slave(shub, slave);
}

static void
process_fds(struct shub *shub)
{
	/*
	 * TODO: This part is almost same as fmhub/main.c (process_fds). Share
	 * code with it.
	 */
	struct slave *slave;
	fd_set fds;
	int i, max_fd, n, nfds, rfd;

	FD_ZERO(&fds);

	rfd = shub->mhub.rfd;
	FD_SET(rfd, &fds);
	max_fd = rfd;

	slave = (struct slave *)FIRST_ITEM(&shub->slaves);
	while (ITEM_NEXT(slave) != NULL) {
		rfd = slave->rfd;
		FD_SET(rfd, &fds);
		max_fd = MAX(max_fd, rfd);
		slave = (struct slave *)ITEM_NEXT(slave);
	}
	nfds = max_fd + 1;
	n = select(nfds, &fds, NULL, NULL, NULL);
	if (n == -1)
		die(-1, "select failed");
	for (i = 0; i < nfds; i++)
		process_fd(shub, i, &fds);
}

static void
mainloop(struct shub *shub)
{
	while (FIRST_ITEM(&shub->slaves)->next != NULL)
		process_fds(shub);
}

static int
shub_main(struct shub *shub)
{
	struct slave *slave = (struct slave *)FIRST_ITEM(&shub->slaves);

	negotiate_version_with_mhub(shub);
	negotiate_version_with_slave(slave);
	read_pids(shub, slave);
	transport_fds(slave->rfd, shub->mhub.wfd);

	mainloop(shub);

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
	int opt, status;
	char **args;

	openlog(argv[0], LOG_PID, LOG_USER);
	log_start_message(argc, argv);

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
	if (argc - optind != 5) {
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

	status = shub_main(&shub);
	log_graceful_exit(status);

	return (status);
}

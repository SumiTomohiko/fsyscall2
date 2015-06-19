#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
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
	pair_id_t pair_id;
};

#define	TOKEN_SIZE	64

struct fork_info {
	struct item item;
	char token[TOKEN_SIZE];
	pair_id_t pair_id;
};

struct shub {
	struct connection mhub;
	struct list slaves;
	int fork_sock;
	struct list fork_info;
};

static void
log_fds(const char *label, int rfd, int wfd)
{
	const char *fmt = "fds for %s are %d (read) and %d (write)";

	syslog(LOG_DEBUG, fmt, label, rfd, wfd);
}

static void
usage()
{
	puts("fshub mhub_rfd mhub_wfd slave_rfd slave_wfd sock_path");
}

static void
negotiate_version_with_mhub(struct shub *shub)
{
	uint8_t request;
	uint8_t ver = 0;

	write_or_die(shub->mhub.wfd, &ver, sizeof(ver));
	read_or_die(shub->mhub.rfd, &request, sizeof(request));
	assert(request == 0);
	syslog(LOG_INFO, "protocol version for mhub is %d.", ver);
}

static void
negotiate_version_with_slave(struct slave *slave)
{
	uint8_t request, ver = 0;

	read_or_die(slave->rfd, &request, sizeof(request));
	assert(request == 0);
	write_or_die(slave->wfd, &ver, sizeof(ver));
	syslog(LOG_INFO, "protocol version for slave is %d.", ver);
}

static void
read_pids(struct shub *shub, struct slave *slave)
{
	slave->pair_id = read_pair_id(shub->mhub.rfd);
}

static bool
compare_rfd(struct item *item, void *bonus)
{
	struct slave *slave = (struct slave *)item;
	int *pfd = (int *)bonus;

	return (slave->rfd == *pfd);
}

static struct slave *
find_slave_of_rfd(struct shub *shub, int rfd)
{
	struct item *item;

	item = list_search(&shub->slaves, compare_rfd, (void *)&rfd);
	assert(item != NULL);

	return (struct slave *)item;
}

static bool
compare_pair_id(struct item *item, void *bonus)
{
	struct slave *slave = (struct slave *)item;
	pair_id_t *pid = (pair_id_t *)bonus;

	return (slave->pair_id == *pid);
}

static struct slave *
find_slave_of_pair_id(struct shub *shub, pair_id_t pair_id)
{
	struct item *item;

	item = list_search(&shub->slaves, compare_pair_id, (void *)&pair_id);
	assert(item != NULL);

	return (struct slave *)item;
}

static void
dispose_slave(struct slave *slave)
{

	REMOVE_ITEM(slave);
	hub_close_fds_or_die(slave->rfd, slave->wfd);
	free(slave);
}

static void
transfer_payload_to_slave(struct shub *shub, command_t cmd)
{
	pair_id_t pair_id;
	uint32_t payload_size;
	int len, rfd, wfd;
	char buf[FSYSCALL_BUFSIZE_INT32];
	const char *fmt = "%s: pair_id=%ld, payload_size=%u", *name;

	rfd = shub->mhub.rfd;
	pair_id = read_pair_id(rfd);
	len = read_numeric_sequence(rfd, buf, array_sizeof(buf));
	payload_size = decode_uint32(buf, len);

	name = get_command_name(cmd);
	syslog(LOG_DEBUG, fmt, name, pair_id, payload_size);

	wfd = find_slave_of_pair_id(shub, pair_id)->wfd;
	write_command(wfd, cmd);
	write_or_die(wfd, buf, len);
	transfer(rfd, wfd, payload_size);
}

static void
process_exit(struct shub *shub)
{
	struct slave *slave;
	pair_id_t pair_id;
	int _, rfd, status, wfd;

	rfd = shub->mhub.rfd;
	pair_id = read_pair_id(rfd);
	slave = find_slave_of_pair_id(shub, pair_id);
	status = read_int32(rfd, &_);
	syslog(LOG_DEBUG, "EXIT_CALL: pair_id=%ld, status=%d", pair_id, status);

	wfd = slave->wfd;
	write_command(wfd, EXIT_CALL);
	write_int32(wfd, status);

	dispose_slave(slave);
}

static bool
compare_token(struct item *item, void *bonus)
{
	struct fork_info *fi = (struct fork_info *)item;
	const char *token = (const char *)bonus;

	return (strcmp(fi->token, token) == 0);
}

static struct fork_info *
find_fork_info_or_die(struct shub *shub, const char *token)
{
	struct item *item;

	item = list_search(&shub->fork_info, compare_token, (void *)token);
	if (item == NULL)
		die(1, "Cannot find fork_info for %s", token);

	return (struct fork_info *)item;
}

static void
process_fork_socket(struct shub *shub)
{
	struct slave *slave;
	struct sockaddr_storage addr;
	struct fork_info *fi;
	socklen_t addrlen;
	pair_id_t pair_id;
	int fd;
	char name[64], token[TOKEN_SIZE];

	addrlen = sizeof(addr);
	fd = accept(shub->fork_sock, (struct sockaddr *)&addr, &addrlen);
	if (fd < 0)
		die(1, "Cannot accept(2)");
	read_or_die(fd, token, sizeof(token));
	fi = find_fork_info_or_die(shub, token);
	syslog(LOG_INFO, "A trusted slave has been connected.");

	slave = (struct slave *)malloc_or_die(sizeof(*slave));
	slave->rfd = slave->wfd = fd;
	pair_id = slave->pair_id = fi->pair_id;
	PREPEND_ITEM(&shub->slaves, slave);
	snprintf(name, sizeof(name), "the new slave (pair id: %lu)", pair_id);
	log_fds(name, slave->rfd, slave->wfd);

	REMOVE_ITEM(fi);
	free(fi);
}

static void
process_fork(struct shub *shub)
{
	struct fork_info *fork_info;
	pair_id_t child_pair_id, pair_id;
	int rfd, wfd;
	const char *fmt = "FORK_CALL: pair_id=%ld";
	char *token;

	rfd = shub->mhub.rfd;
	pair_id = read_pair_id(rfd);
	read_payload_size(rfd);	// unused
	child_pair_id = read_pair_id(rfd);

	syslog(LOG_DEBUG, fmt, pair_id);

	fork_info = (struct fork_info *)malloc_or_die(sizeof(*fork_info));
	token = fork_info->token;
	hub_generate_token(token, sizeof(token));
	fork_info->pair_id = child_pair_id;
	PREPEND_ITEM(&shub->fork_info, fork_info);

	wfd = find_slave_of_pair_id(shub, pair_id)->wfd;
	write_command(wfd, FORK_CALL);
	write_payload_size(wfd, TOKEN_SIZE);
	write_or_die(wfd, token, TOKEN_SIZE);

	process_fork_socket(shub);
}

static void
process_mhub(struct shub *shub)
{
	command_t cmd;
	const char *fmt = "processing %s from the master";

	cmd = read_command(shub->mhub.rfd);
	syslog(LOG_DEBUG, fmt, get_command_name(cmd));
	switch (cmd) {
	case EXIT_CALL:
		process_exit(shub);
		break;
	case FORK_CALL:
		process_fork(shub);
		break;
	case POLL_CALL:
	case SELECT_CALL:
	case CONNECT_CALL:
	case BIND_CALL:
	case GETPEERNAME_CALL:
	case GETSOCKNAME_CALL:
	case SIGACTION_CALL:
	case ACCEPT_CALL:
	case GETSOCKOPT_CALL:
	case SETSOCKOPT_CALL:
	case KEVENT_CALL:
#include "dispatch_call.inc"
		transfer_payload_to_slave(shub, cmd);
		break;
	default:
		diex(-1, "unknown command (%d) from the master hub", cmd);
		/* NOTREACHED */
	}
}

static void
process_signaled(struct shub *shub, struct slave *slave, command_t cmd)
{
	int wfd;
	char sig;

	read_or_die(slave->rfd, &sig, sizeof(sig));
	syslog(LOG_DEBUG, "signal: %d (SIG%s)", sig, sys_signame[(int)sig]);

	wfd = shub->mhub.wfd;
	write_command(wfd, cmd);
	write_pair_id(wfd, slave->pair_id);
	write_or_die(wfd, &sig, sizeof(sig));
}

static void
transfer_payload_from_slave(struct shub *shub, struct slave *slave, command_t cmd)
{
	uint32_t payload_size;
	int len, rfd, wfd;
	char buf[FSYSCALL_BUFSIZE_UINT32];
	const char *name;

	rfd = slave->rfd;
	len = read_numeric_sequence(rfd, buf, array_sizeof(buf));
	payload_size = decode_uint32(buf, len);

	name = get_command_name(cmd);
	syslog(LOG_DEBUG, "%s: payload_size=%u", name, payload_size);

	wfd = shub->mhub.wfd;
	write_command(wfd, cmd);
	write_pair_id(wfd, slave->pair_id);
	write_or_die(wfd, buf, len);
	transfer(rfd, wfd, payload_size);
}

static void
process_slave(struct shub *shub, struct slave *slave)
{
	pair_id_t pair_id;
	command_t cmd;
	int rfd;
	const char *errfmt = "unknown command (%d) from slave %ld";
	const char *fmt = "the slave of pair id %ld (rfd %d) is ready to read";
	const char *fmt2 = "processing %s from the slave of pair id %d";

	pair_id = slave->pair_id;
	rfd = slave->rfd;
	syslog(LOG_DEBUG, fmt, pair_id, rfd);

	cmd = read_command(slave->rfd);
	syslog(LOG_DEBUG, fmt2, get_command_name(cmd), pair_id);
	switch (cmd) {
	case SIGNALED:
		process_signaled(shub, slave, cmd);
		break;
	case FORK_RETURN:
	case POLL_RETURN:
	case SELECT_RETURN:
	case CONNECT_RETURN:
	case BIND_RETURN:
	case GETPEERNAME_RETURN:
	case GETSOCKNAME_RETURN:
	case SIGACTION_RETURN:
	case ACCEPT_RETURN:
	case GETSOCKOPT_RETURN:
	case SETSOCKOPT_RETURN:
	case KEVENT_RETURN:
#include "dispatch_ret.inc"
		transfer_payload_from_slave(shub, slave, cmd);
		break;
	default:
		diex(-1, errfmt, cmd, slave->pair_id);
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
	fd_set fds, *pfds;
	int fork_sock, i, max_fd, n, nfds, rfd;

	pfds = &fds;
	FD_ZERO(pfds);

	rfd = shub->mhub.rfd;
	FD_SET(rfd, pfds);
	fork_sock = shub->fork_sock;
	FD_SET(fork_sock, pfds);

	max_fd = MAX(rfd, fork_sock);
	slave = (struct slave *)FIRST_ITEM(&shub->slaves);
	while (!IS_LAST(slave)) {
		rfd = slave->rfd;
		FD_SET(rfd, pfds);
		max_fd = MAX(max_fd, rfd);
		slave = (struct slave *)ITEM_NEXT(slave);
	}
	nfds = max_fd + 1;
	n = select(nfds, pfds, NULL, NULL, NULL);
	if (n == -1)
		die(-1, "select failed");
	for (i = 0; i < nfds; i++)
		process_fd(shub, i, pfds);
}

static void
mainloop(struct shub *shub)
{
	while (!IS_EMPTY(&shub->slaves) || !IS_EMPTY(&shub->fork_info))
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
ignore_sigpipe()
{
	/*
	 * Assume a session including two or more slaves. The parent slave can
	 * be signaled with SIGCHLD even after all of the master ended. If the
	 * shub writes a SIGNALED command to a disconnected master, it causes
	 * SIGPIPE which terminates the shub process. So the shub ignores
	 * SIGPIPE to avoid being terminated (and libio ignores EPIPE in
	 * write(2)).
	 */
	struct sigaction act;

	act.sa_handler = SIG_IGN;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	if (sigaction(SIGPIPE, &act, NULL) == -1)
		die(1, "sigaction(2) for SIGPIPE");
}

int
main(int argc, char *argv[])
{
	struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	struct shub *pshub, shub;
	int fork_sock, opt, status;
	const char *sock_path;
	char **args;

	pshub = &shub;

	openlog(argv[0], LOG_PID, LOG_USER);
	log_start_message(argc, argv);

	while ((opt = getopt_long(argc, argv, "+", opts, NULL)) != -1)
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
	pshub->mhub.rfd = atoi_or_die(args[0], "mhub_rfd");
	pshub->mhub.wfd = atoi_or_die(args[1], "mhub_wfd");
	log_fds("mhub", pshub->mhub.rfd, pshub->mhub.wfd);

	initialize_list(&pshub->slaves);
	struct slave *slave = (struct slave *)malloc_or_die(sizeof(*slave));
	slave->rfd = atoi_or_die(args[2], "slave_rfd");
	slave->wfd = atoi_or_die(args[3], "slave_wfd");
	PREPEND_ITEM(&pshub->slaves, slave);
	log_fds("slave", slave->rfd, slave->wfd);

	sock_path = args[4];
	pshub->fork_sock = fork_sock = hub_open_fork_socket(sock_path);
	initialize_list(&pshub->fork_info);
	ignore_sigpipe();
	status = shub_main(pshub);
	hub_close_fork_socket(fork_sock);
	hub_unlink_socket(sock_path);
	log_graceful_exit(status);

	return (status);
}

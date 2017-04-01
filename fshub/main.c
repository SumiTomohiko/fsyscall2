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
#include <time.h>

#include <fsyscall.h>
#include <fsyscall/private.h>
#include <fsyscall/private/atoi_or_die.h>
#include <fsyscall/private/close_or_die.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/hub.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/io_or_die.h>
#include <fsyscall/private/list.h>
#include <fsyscall/private/log.h>
#include <fsyscall/private/malloc_or_die.h>

struct slave {
	struct item item;
	struct io io;
	pair_id_t pair_id;
	bool exited;
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
	struct io **ios;
	int fork_sock;
	int nslaves;
	struct list fork_info;
	time_t last_send_time;
	time_t last_recv_time;
};

static void
log_io(const char *label, const struct io *io)
{
	char buf[256];

	io_dump(io, buf, sizeof(buf));
	syslog(LOG_DEBUG, "io for %s is %s", label, buf);
}

static void
usage()
{
	puts("fshub mhub_rfd mhub_wfd slave_rfd slave_wfd sock_path");
}

static void
negotiate_version_with_mhub(struct shub *shub)
{
	struct io *io;
	uint8_t request;
	uint8_t ver = 0;

	io = shub->mhub.conn_io;
	write_or_die(io, &ver, sizeof(ver));
	read_or_die(io, &request, sizeof(request));
	assert(request == 0);
	syslog(LOG_INFO, "protocol version for mhub is %d.", ver);
}

static void
negotiate_version_with_slave(struct slave *slave)
{
	struct io *io;
	uint8_t request, ver = 0;

	io = &slave->io;
	read_or_die(io, &request, sizeof(request));
	assert(request == 0);
	write_or_die(io, &ver, sizeof(ver));
	syslog(LOG_INFO, "protocol version for slave is %d.", ver);
}

static void
read_pids(struct shub *shub, struct slave *slave)
{
	slave->pair_id = read_pair_id(shub->mhub.conn_io);
}

static bool
compare_io(struct item *item, void *bonus)
{
	struct slave *slave = (struct slave *)item;

	return (&slave->io == bonus);
}

static struct slave *
find_slave_of_io(struct shub *shub, struct io *io)
{
	struct item *item;

	item = list_search(&shub->slaves, compare_io, io);
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
alloc_ios(struct shub *shub)
{
	size_t size;

	free(shub->ios);

	size = sizeof(struct io *) * (shub->nslaves + 1);
	shub->ios = (struct io **)malloc_or_die(size);
}

static void
dispose_slave(struct shub *shub, struct slave *slave)
{

	shub->nslaves--;
	alloc_ios(shub);

	REMOVE_ITEM(slave);
	hub_close_fds_or_die(&slave->io);
	free(slave);
}

static void
transfer_simple_command_to_slave(struct shub *shub, command_t cmd)
{
	pair_id_t pair_id;

	pair_id = read_pair_id(shub->mhub.conn_io);
	syslog(LOG_DEBUG, "%s: pair_id=%ld", get_command_name(cmd), pair_id);

	write_command(&find_slave_of_pair_id(shub, pair_id)->io, cmd);
}

static void
transfer_payload_to_slave(struct shub *shub, command_t cmd)
{
	struct io *dst, *src;
	pair_id_t pair_id;
	uint32_t payload_size;
	int len;
	char buf[FSYSCALL_BUFSIZE_INT32];
	const char *fmt = "%s: pair_id=%ld, payload_size=%u", *name;

	src = shub->mhub.conn_io;
	pair_id = read_pair_id(src);
	len = read_numeric_sequence(src, buf, array_sizeof(buf));
	payload_size = decode_uint32(buf, len);

	name = get_command_name(cmd);
	syslog(LOG_DEBUG, fmt, name, pair_id, payload_size);

	dst = &find_slave_of_pair_id(shub, pair_id)->io;
	write_command(dst, cmd);
	write_or_die(dst, buf, len);
	transfer(src, dst, payload_size);
}

static void
process_thr_exit(struct shub *shub)
{
	struct slave *slave;
	pair_id_t pair_id;

	pair_id = read_pair_id(shub->mhub.conn_io);
	slave = find_slave_of_pair_id(shub, pair_id);
	syslog(LOG_DEBUG, "THR_EXIT_CALL: pair_id=%ld", pair_id);

	write_command(&slave->io, THR_EXIT_CALL);

	slave->exited = true;
}

static void
process_exit(struct shub *shub)
{
	struct slave *slave;
	struct io *dst, *src;
	payload_size_t _;
	pair_id_t pair_id;
	int status;

	src = shub->mhub.conn_io;
	pair_id = read_pair_id(src);
	slave = find_slave_of_pair_id(shub, pair_id);
	status = read_int32(src, &_);
	syslog(LOG_DEBUG, "EXIT_CALL: pair_id=%ld, status=%d", pair_id, status);

	dst = &slave->io;
	write_command(dst, EXIT_CALL);
	write_int32(dst, status);

	slave->exited = true;
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

static struct slave *
alloc_slave(struct shub *shub)
{
	struct slave *slave;

	slave = (struct slave *)malloc_or_die(sizeof(*slave));
	slave->exited = false;

	shub->nslaves++;
	alloc_ios(shub);

	return (slave);
}

static void
process_fork_socket(struct shub *shub)
{
	struct slave *slave;
	struct sockaddr_storage addr;
	struct fork_info *fi;
	struct io io;
	socklen_t addrlen;
	pair_id_t pair_id;
	int fd;
	char name[64], token[TOKEN_SIZE];

	addrlen = sizeof(addr);
	fd = accept(shub->fork_sock, (struct sockaddr *)&addr, &addrlen);
	if (fd < 0)
		die(1, "Cannot accept(2)");
	io_init_nossl(&io, fd, fd, vsyslog);
	read_or_die(&io, token, sizeof(token));
	fi = find_fork_info_or_die(shub, token);
	syslog(LOG_INFO, "A trusted slave has been connected.");

	slave = alloc_slave(shub);
	io_init_nossl(&slave->io, fd, fd, vsyslog);
	pair_id = slave->pair_id = fi->pair_id;
	PREPEND_ITEM(&shub->slaves, slave);
	snprintf(name, sizeof(name), "the new slave (pair id: %lu)", pair_id);
	log_io(name, &slave->io);

	REMOVE_ITEM(fi);
	free(fi);
}

static void
transfer_token(struct shub *shub, command_t cmd)
{
	struct fork_info *fork_info;
	struct io *dst, *src;
	pair_id_t child_pair_id, pair_id;
	const char *fmt = "%s: pair_id=%ld";
	char *token;

	src = shub->mhub.conn_io;
	pair_id = read_pair_id(src);
	read_payload_size(src);	// unused
	child_pair_id = read_pair_id(src);

	syslog(LOG_DEBUG, fmt, get_command_name(cmd), pair_id);

	fork_info = (struct fork_info *)malloc_or_die(sizeof(*fork_info));
	token = fork_info->token;
	hub_generate_token(token, sizeof(token));
	fork_info->pair_id = child_pair_id;
	PREPEND_ITEM(&shub->fork_info, fork_info);

	dst = &find_slave_of_pair_id(shub, pair_id)->io;
	write_command(dst, cmd);
	write_payload_size(dst, TOKEN_SIZE);
	write_or_die(dst, token, TOKEN_SIZE);

	process_fork_socket(shub);
}

static int
process_mhub(struct shub *shub)
{
	command_t cmd;
	const char *fmt = "processing %s from the master";

	if (io_read_command(shub->mhub.conn_io, &cmd) == -1)
		return (-1);
	syslog(LOG_DEBUG, fmt, get_command_name(cmd));
	switch (cmd) {
	case KEEPALIVE:
		break;
	case EXIT_CALL:
		process_exit(shub);
		break;
	case FORK_CALL:
	case THR_NEW_CALL:
		transfer_token(shub, cmd);
		break;
	case CLOSE_CALL:
	case POLL_CALL:
	case SELECT_CALL:
	case CONNECT_CALL:
	case BIND_CALL:
	case GETPEERNAME_CALL:
	case GETSOCKNAME_CALL:
	case ACCEPT_CALL:
	case GETSOCKOPT_CALL:
	case SETSOCKOPT_CALL:
	case KEVENT_CALL:
	case POLL_START:
	case SIGPROCMASK_CALL:
	case SENDMSG_CALL:
	case RECVMSG_CALL:
	case UTIMES_CALL:
	case GETDIRENTRIES_CALL:
	case FCNTL_CALL:
	case OPENAT_CALL:
	case ACCEPT4_CALL:
#include "dispatch_call.inc"
		transfer_payload_to_slave(shub, cmd);
		break;
	case POLL_END:
		transfer_simple_command_to_slave(shub, cmd);
		break;
	case THR_EXIT_CALL:
		process_thr_exit(shub);
		break;
	default:
		diex(-1, "unknown command (%d) from the master hub", cmd);
		/* NOTREACHED */
	}

	shub->last_recv_time = time(NULL);

	return (0);
}

static void
write_signaled(struct shub *shub, struct slave *slave, char sig)
{
	struct io *io;

	io = shub->mhub.conn_io;
	write_command(io, SIGNALED);
	write_pair_id(io, slave->pair_id);
	write_or_die(io, &sig, sizeof(sig));
}

static int
process_signaled(struct shub *shub, struct slave *slave)
{
	char sig;

	read_or_die(&slave->io, &sig, sizeof(sig));
	syslog(LOG_DEBUG, "signal: %d (SIG%s)", sig, sys_signame[(int)sig]);

	write_signaled(shub, slave, sig);

	return (0);
}

static int
transfer_payload_from_slave(struct shub *shub, struct slave *slave,
			    command_t cmd)
{
	struct io *dst, *src;
	uint32_t payload_size;
	int len;
	char buf[FSYSCALL_BUFSIZE_UINT32];
	const char *name;

	src = &slave->io;
	len = io_read_numeric_sequence(src, buf, array_sizeof(buf));
	if (len == -1)
		return (-1);
	payload_size = decode_uint32(buf, len);

	name = get_command_name(cmd);
	syslog(LOG_DEBUG, "%s: payload_size=%u", name, payload_size);

	dst = shub->mhub.conn_io;
	write_command(dst, cmd);
	write_pair_id(dst, slave->pair_id);
	write_or_die(dst, buf, len);
	if (io_transfer(src, dst, payload_size) == -1)
		return (-1);

	return (0);
}

static int
process_slave(struct shub *shub, struct slave *slave)
{
	pair_id_t pair_id;
	command_t cmd;
	int status;
	const char *errfmt = "unknown command (%d) from slave %ld";
	const char *fmt = "the slave of pair id %ld is ready to read";
	const char *fmt2 = "processing %s from the slave of pair id %d";

	pair_id = slave->pair_id;
	syslog(LOG_DEBUG, fmt, pair_id);

	if (io_read_command(&slave->io, &cmd) == -1)
		return (-1);
	syslog(LOG_DEBUG, fmt2, get_command_name(cmd), pair_id);
	switch (cmd) {
	case SIGNALED:
		status = process_signaled(shub, slave);
		break;
	case FORK_RETURN:
	case CLOSE_RETURN:
	case POLL_RETURN:
	case SELECT_RETURN:
	case CONNECT_RETURN:
	case BIND_RETURN:
	case GETPEERNAME_RETURN:
	case GETSOCKNAME_RETURN:
	case ACCEPT_RETURN:
	case GETSOCKOPT_RETURN:
	case SETSOCKOPT_RETURN:
	case KEVENT_RETURN:
	case POLL_ENDED:
	case SIGPROCMASK_RETURN:
	case SENDMSG_RETURN:
	case RECVMSG_RETURN:
	case THR_NEW_RETURN:
	case UTIMES_RETURN:
	case GETDIRENTRIES_RETURN:
	case FCNTL_RETURN:
	case OPENAT_RETURN:
	case ACCEPT4_RETURN:
#include "dispatch_ret.inc"
		status = transfer_payload_from_slave(shub, slave, cmd);
		break;
	default:
		diex(-1, errfmt, cmd, slave->pair_id);
		status = -1;
	}

	shub->last_send_time = time(NULL);

	return (status);
}

static int
process_fd(struct shub *shub, struct io *io)
{
	/*
	 * TODO: This part is almost same as fmhub/main.c (process_fd). Share
	 * code with it.
	 */
	struct slave *slave;

	if (!io_is_readable(io))
		return (0);
	if (shub->mhub.conn_io == io)
		return (process_mhub(shub));

	slave = find_slave_of_io(shub, io);
	if (process_slave(shub, slave) == -1) {
		/*
		 * If a slave died without exit(2) calling, here assumes that
		 * the slave was killed by SIGKILL.
		 */
		if (!slave->exited)
			write_signaled(shub, slave, SIGKILL);
		dispose_slave(shub, slave);
	}

	return (0);
}

static void
write_keepalive(struct shub *shub)
{

	write_command(shub->mhub.conn_io, KEEPALIVE);
}

static int
process_fds(struct shub *shub)
{
	/*
	 * TODO: This part is almost same as fmhub/main.c (process_fds). Share
	 * code with it.
	 */
	struct slave *slave;
	struct io **ios;
	struct timeval timeout;
	time_t abort_time, next_keepalive_time, now, now2;
	int error, i, n, nios;

	ios = shub->ios;
	ios[0] = shub->mhub.conn_io;

	slave = (struct slave *)FIRST_ITEM(&shub->slaves);
	i = 1;
	while (!IS_LAST(slave)) {
		ios[i] = &slave->io;
		slave = (struct slave *)ITEM_NEXT(slave);
		i++;
	}

	next_keepalive_time = shub->last_send_time + KEEPALIVE_INTERVAL;
	abort_time = shub->last_recv_time + ABORT_SEC;
	now = time(NULL);
	timeout.tv_sec = MAX(MIN(next_keepalive_time - now, abort_time - now),
			     0);
	timeout.tv_usec = 0;

	nios = shub->nslaves + 1;
	n = io_select(nios, ios, &timeout, &error);
	switch (n) {
	case -1:
		diec(1, error, "select failed");
	case 0:
		now2 = time(NULL);
		if (abort_time <= now2)
			diec(1, error, "master does not response");
		if (next_keepalive_time <= now2) {
			write_keepalive(shub);
			shub->last_send_time = time(NULL);
		}
		break;
	default:
		for (i = 0; i < nios; i++)
			if (process_fd(shub, ios[i]) == -1)
				return (-1);
		break;
	}

	return (0);
}

static void
mainloop(struct shub *shub)
{
	while (!IS_EMPTY(&shub->slaves) || !IS_EMPTY(&shub->fork_info))
		if (process_fds(shub) == -1)
			break;
}

static int
shub_main(struct shub *shub)
{
	struct slave *slave = (struct slave *)FIRST_ITEM(&shub->slaves);

	negotiate_version_with_mhub(shub);
	negotiate_version_with_slave(slave);
	read_pids(shub, slave);
	transport_fds(&slave->io, shub->mhub.conn_io);

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
	struct slave *slave;
	struct io io;
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
	io_init_nossl(&io, atoi_or_die(args[0], "mhub_rfd"),
		      atoi_or_die(args[1], "mhub_wfd"), vsyslog);
	pshub->mhub.conn_io = &io;
	log_io("mhub", pshub->mhub.conn_io);

	initialize_list(&pshub->slaves);
	pshub->ios = NULL;
	pshub->nslaves = 0;
	slave = alloc_slave(pshub);
	io_init_nossl(&slave->io, atoi_or_die(args[2], "slave_rfd"),
		      atoi_or_die(args[3], "slave_wfd"), vsyslog);
	PREPEND_ITEM(&pshub->slaves, slave);
	log_io("slave", &slave->io);

	sock_path = args[4];
	pshub->fork_sock = fork_sock = hub_open_fork_socket(sock_path);
	initialize_list(&pshub->fork_info);
	ignore_sigpipe();
	pshub->last_send_time = pshub->last_recv_time = time(NULL);
	status = shub_main(pshub);
	hub_close_fork_socket(fork_sock);
	hub_unlink_socket(sock_path);
	log_graceful_exit(status);

	return (status);
}

#include <sys/types.h>
#include <sys/uio.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include <fsyscall.h>
#include <fsyscall/private.h>
#include <fsyscall/private/atoi_or_die.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fslave.h>
#include <fsyscall/private/fslave/proto.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/log.h>

static void
usage()
{
	puts("fslave rfd wfd path");
}

void
die_if_payload_size_mismatched(int expected, int actual)
{
	if (expected == actual)
		return;
	diec(-1, EPROTO, "Payload size mismatched");
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
is_alive_fd(struct slave *slave, int fd)
{
	if ((slave->rfd == fd) || (slave->wfd == fd))
		return (false);
	if (fcntl(fd, F_GETFL) != -1)
		return (true);
	if (errno != EBADF)
		die(-1, "Cannot fcntl(%d, F_GETFL)", fd);
	return (false);
}

static int
count_alive_fds(struct slave *slave)
{
	int i, n = 0, size;

	size = getdtablesize();
	for (i = 0; i < size; i++)
		n += is_alive_fd(slave, i) ? 1 : 0;

	return (n);
}

static int
encode_alive_fd(struct slave *slave, int fd, char *dest, int size)
{
	if (is_alive_fd(slave, fd))
		return (encode_int32(fd, dest, size));
	return (0);
}

static void
write_open_fds(struct slave *slave)
{
	size_t buf_size;
	int i, nfds, pos, wfd;
	char *buf;

	buf_size = count_alive_fds(slave) * FSYSCALL_BUFSIZE_INT32;
	buf = (char *)alloca(buf_size);

	pos = 0;
	nfds = getdtablesize();
	for (i = 0; i < nfds; i++)
		pos += encode_alive_fd(slave, i, buf + pos, buf_size - pos);

	assert(0 <= pos);
	wfd = slave->wfd;
	write_int32(wfd, pos);
	write_or_die(wfd, buf, pos);
}

void
return_generic(struct slave *slave, command_t cmd, ssize_t ret, int errnum)
{
	int errnum_len, ret_len, wfd;
	char errnum_buf[FSYSCALL_BUFSIZE_INT32];
	char ret_buf[FSYSCALL_BUFSIZE_INT64];
	const char *fmt = "%s: ret=%zd, errnum=%d";

	syslog(LOG_DEBUG, fmt, get_command_name(cmd), ret, errnum);

	ret_len = encode_int64(ret, ret_buf, array_sizeof(ret_buf));
	errnum_len = (ret == -1) ? encode_int32(
			errnum,
			errnum_buf,
			array_sizeof(errnum_buf)) : 0;

	wfd = slave->wfd;
	write_command(wfd, cmd);
	write_payload_size(wfd, ret_len + errnum_len);
	write_or_die(wfd, ret_buf, ret_len);
	write_or_die(wfd, errnum_buf, errnum_len);
}

static void
return_read(struct slave *slave, ssize_t ret, const char *buf)
{
	int ret_len, wfd;
	char ret_buf[FSYSCALL_BUFSIZE_INT64];

	ret_len = encode_int64(ret, ret_buf, array_sizeof(ret_buf));

	syslog(LOG_DEBUG, "ret=%zd, ret_len=%d", ret, ret_len);
	wfd = slave->wfd;
	write_command(wfd, RET_READ);
	write_payload_size(wfd, ret_len + ret);
	write_or_die(wfd, ret_buf, ret_len);
	write_or_die(wfd, buf, ret);
}

static void
process_read(struct slave *slave)
{
	int fd, fd_len, nbytes_len, rfd;
	payload_size_t payload_size;
	size_t nbytes;
	ssize_t ret;
	char *buf;

	syslog(LOG_DEBUG, "Processing CMD_READ.");

	rfd = slave->rfd;
	payload_size = read_payload_size(rfd);
	fd = read_int32(rfd, &fd_len);
	nbytes = read_uint64(rfd, &nbytes_len);
	syslog(LOG_DEBUG, "CMD_READ: fd=%d, nbytes=%zu", fd, nbytes);
	die_if_payload_size_mismatched(payload_size, fd_len + nbytes_len);

	buf = (char *)alloca(sizeof(char) * nbytes);
	ret = read(fd, buf, nbytes);
	if (ret == -1) {
		return_generic(slave, RET_READ, ret, errno);
		return;
	}

	return_read(slave, ret, buf);
}

static int
process_exit(struct slave *slave)
{
	int _, status;

	syslog(LOG_DEBUG, "Processing CALL_EXIT.");

	status = read_int32(slave->rfd, &_);

	syslog(LOG_DEBUG, "CALL_EXIT: status=%d", status);

	return (status);
}

static int
mainloop(struct slave *slave)
{
	command_t cmd;
	int rfd;

	rfd = slave->rfd;
	for (;;) {
		cmd = read_command(rfd);
		switch (cmd) {
		case CALL_ACCESS:
			process_access(slave);
			break;
		case CALL_CLOSE:
			process_close(slave);
			break;
		case CALL_EXIT:
			return process_exit(slave);
		case CALL_OPEN:
			process_open(slave);
			break;
		case CALL_READ:
			process_read(slave);
			break;
		case CALL_WRITE:
			process_write(slave);
			break;
		default:
			diex(-1, "Unknown command (%d)", cmd);
			/* NOTREACHED */
		}
	}

	return (-1);
}

static int
slave_main(struct slave *slave)
{
	negotiate_version(slave);
	write_pid(slave->wfd, getpid());
	write_open_fds(slave);

	return (mainloop(slave));
}

static void
signal_handler(int sig)
{
	assert(sig == SIGPIPE);
	diex(-1, "Signaled SIGPIPE.");
	/* NOTREACHED */
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
			printf("fslave %s\n", FSYSCALL_VERSION);
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
	slave.rfd = atoi_or_die(args[0], "rfd");
	slave.wfd = atoi_or_die(args[1], "wfd");
	slave.path = args[2];

	status = slave_main(&slave);
	log_graceful_exit(status);

	return (status);
}

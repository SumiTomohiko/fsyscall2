#include <sys/select.h>
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
#include <fsyscall/private/malloc_or_die.h>
#include <fsyscall/private/select.h>

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
	syslog(LOG_INFO, "protocol version for shub is %d.", response);
}

static bool
is_alive_fd(struct slave *slave, int fd)
{
	if ((slave->rfd == fd) || (slave->wfd == fd))
		return (false);
	if (fcntl(fd, F_GETFL) != -1)
		return (true);
	if (errno != EBADF)
		die(-1, "cannot fcntl(%d, F_GETFL)", fd);
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

static void
return_generic(struct slave *slave, command_t cmd, char *ret_buf, int ret_len, char *errnum_buf, int errnum_len)
{
	int wfd;

	wfd = slave->wfd;
	write_command(wfd, cmd);
	write_payload_size(wfd, ret_len + errnum_len);
	write_or_die(wfd, ret_buf, ret_len);
	write_or_die(wfd, errnum_buf, errnum_len);
}

void
return_int(struct slave *slave, command_t cmd, int ret, int errnum)
{
	int errnum_len, ret_len;
	char errnum_buf[FSYSCALL_BUFSIZE_INT32];
	char ret_buf[FSYSCALL_BUFSIZE_INT32];
	const char *fmt = "%s: ret=%d, errnum=%d";

	syslog(LOG_DEBUG, fmt, get_command_name(cmd), ret, errnum);

	ret_len = encode_int32(ret, ret_buf, array_sizeof(ret_buf));
	errnum_len = (ret == -1) ? encode_int32(
			errnum,
			errnum_buf,
			array_sizeof(errnum_buf)) : 0;

	return_generic(slave, cmd, ret_buf, ret_len, errnum_buf, errnum_len);
}

void
return_ssize(struct slave *slave, command_t cmd, ssize_t ret, int errnum)
{
	int errnum_len, ret_len;
	char errnum_buf[FSYSCALL_BUFSIZE_INT32];
	char ret_buf[FSYSCALL_BUFSIZE_INT64];
	const char *fmt = "%s: ret=%zd, errnum=%d";

	syslog(LOG_DEBUG, fmt, get_command_name(cmd), ret, errnum);

	ret_len = encode_int64(ret, ret_buf, array_sizeof(ret_buf));
	errnum_len = (ret == -1) ? encode_int32(
			errnum,
			errnum_buf,
			array_sizeof(errnum_buf)) : 0;

	return_generic(slave, cmd, ret_buf, ret_len, errnum_buf, errnum_len);
}

static void
read_fds(struct slave *slave, fd_set *fds, payload_size_t *len)
{
	payload_size_t payload_size;
	int fd, fd_len, i, nfds, nfds_len, rfd;

	rfd = slave->rfd;

	nfds = read_int32(rfd, &nfds_len);
	payload_size = nfds_len;

	for (i = 0; i < nfds; i++) {
		fd = read_int32(rfd, &fd_len);
		payload_size += fd_len;
		FD_SET(fd, fds);
	}

	*len = payload_size;
}

static void
read_select_parameters(struct slave *slave, int *nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout, struct timeval **ptimeout)
{
	payload_size_t actual_payload_size, exceptfds_len, payload_size;
	payload_size_t readfds_len, writefds_len;
	int nfds_len, rfd, timeout_status, timeout_status_len, tv_sec_len;
	int tv_usec_len;

	rfd = slave->rfd;
	actual_payload_size = 0;
	payload_size = read_payload_size(rfd);

	*nfds = read_int32(rfd, &nfds_len);
	actual_payload_size += nfds_len;

	read_fds(slave, readfds, &readfds_len);
	actual_payload_size += readfds_len;
	read_fds(slave, writefds, &writefds_len);
	actual_payload_size += writefds_len;
	read_fds(slave, exceptfds, &exceptfds_len);
	actual_payload_size += exceptfds_len;

	timeout_status = read_int32(rfd, &timeout_status_len);
	actual_payload_size += timeout_status_len;

	if (timeout_status == 0)
		*ptimeout = NULL;
	else {
		assert(timeout_status == 1);

		timeout->tv_sec = read_int64(rfd, &tv_sec_len);
		actual_payload_size += tv_sec_len;
		timeout->tv_usec = read_int64(rfd, &tv_usec_len);
		actual_payload_size += tv_usec_len;

		*ptimeout = timeout;
	}

	die_if_payload_size_mismatched(payload_size, actual_payload_size);
}

static size_t
encode_fds(int nfds, fd_set *fds, char *buf, size_t bufsize)
{
	size_t pos;
	int i;

	pos = 0;
	for (i = 0; i < nfds; i++) {
		if (!FD_ISSET(i, fds))
			continue;
		pos += fsyscall_encode_int32(i, buf + pos, bufsize - pos);
	}

	return (pos);
}

static void
write_select_timeout(struct slave *slave)
{
	payload_size_t retval_len;
	int wfd;
	char retval_buf[FSYSCALL_BUFSIZE_INT32];

	retval_len = fsyscall_encode_int32(0, retval_buf, sizeof(retval_buf));

	wfd = slave->wfd;
	write_command(wfd, RET_SELECT);
	write_payload_size(wfd, retval_len);
	write_or_die(wfd, retval_buf, retval_len);
}

static void
write_select_ready(struct slave *slave, int retval, int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
	payload_size_t exceptfds_len, nexceptfds_len, nreadfds_len;
	payload_size_t nwritefds_len, payload_size, readfds_len, retval_len;
	payload_size_t writefds_len;
	size_t exceptfds_buf_len, readfds_buf_len, writefds_buf_len;
	int nexceptfds, nreadfds, nwritefds, wfd;
	char *exceptfds_buf, nexceptfds_buf[FSYSCALL_BUFSIZE_INT32];
	char nreadfds_buf[FSYSCALL_BUFSIZE_INT32];
	char nwritefds_buf[FSYSCALL_BUFSIZE_INT32], *readfds_buf;
	char retval_buf[FSYSCALL_BUFSIZE_INT32], *writefds_buf;

	nreadfds = fsyscall_count_fds(nfds, readfds);
	nwritefds = fsyscall_count_fds(nfds, writefds);
	nexceptfds = fsyscall_count_fds(nfds, exceptfds);
	readfds_buf_len = fsyscall_compute_fds_bufsize(nreadfds);
	writefds_buf_len = fsyscall_compute_fds_bufsize(nwritefds);
	exceptfds_buf_len = fsyscall_compute_fds_bufsize(nexceptfds);
	readfds_buf = (char *)malloc_or_die(readfds_buf_len);
	writefds_buf = (char *)malloc_or_die(writefds_buf_len);
	exceptfds_buf = (char *)malloc_or_die(exceptfds_buf_len);

#define	ENCODE_INT32(len, n, buf)	do {			\
	len = fsyscall_encode_int32((n), (buf), sizeof(buf));	\
} while (0)
	ENCODE_INT32(retval_len, retval, retval_buf);
	ENCODE_INT32(nreadfds_len, nreadfds, nreadfds_buf);
	ENCODE_INT32(nwritefds_len, nwritefds, nwritefds_buf);
	ENCODE_INT32(nexceptfds_len, nexceptfds, nexceptfds_buf);
#undef	ENCODE_INT32
#define	ENCODE_FDS(len, fds, buf, bufsize)	do {		\
	len = encode_fds(nfds, (fds), (buf), (bufsize));	\
} while (0)
	ENCODE_FDS(readfds_len, readfds, readfds_buf, readfds_buf_len);
	ENCODE_FDS(writefds_len, writefds, writefds_buf, writefds_buf_len);
	ENCODE_FDS(exceptfds_len, exceptfds, exceptfds_buf, exceptfds_buf_len);
#undef	ENCODE_FDS

	wfd = slave->wfd;
	payload_size = retval_len + nreadfds_len + readfds_len + nwritefds_len +
		       writefds_len + nexceptfds_len + exceptfds_len;
	write_command(wfd, RET_SELECT);
	write_payload_size(wfd, payload_size);
	write_or_die(wfd, retval_buf, retval_len);
	write_or_die(wfd, nreadfds_buf, nreadfds_len);
	write_or_die(wfd, readfds_buf, readfds_len);
	write_or_die(wfd, nwritefds_buf, nwritefds_len);
	write_or_die(wfd, writefds_buf, writefds_len);
	write_or_die(wfd, nexceptfds_buf, nexceptfds_len);
	write_or_die(wfd, exceptfds_buf, exceptfds_len);
}

static void
process_select(struct slave *slave)
{
	struct timeval *ptimeout, timeout;
	fd_set exceptfds, readfds, writefds;
	int nfds, retval;

	syslog(LOG_DEBUG, "processing CALL_SELECT.");

	FD_ZERO(&exceptfds);
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	read_select_parameters(slave, &nfds, &readfds, &writefds, &exceptfds, &timeout, &ptimeout);

	retval = select(nfds, &readfds, &writefds, &exceptfds, ptimeout);

	switch (retval) {
	case -1:
		return_int(slave, RET_SELECT, retval, errno);
		break;
	case 0:
		write_select_timeout(slave);
		break;
	default:
		write_select_ready(slave, retval, nfds, &readfds, &writefds, &exceptfds);
		break;
	}
}

static int
process_exit(struct slave *slave)
{
	int _, status;

	syslog(LOG_DEBUG, "processing CALL_EXIT.");

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
#include "dispatch.inc"
		case CALL_SELECT:
			process_select(slave);
			break;
		case CALL_EXIT:
			return process_exit(slave);
		default:
			diex(-1, "unknown command (%d)", cmd);
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
	diex(-1, "signaled SIGPIPE.");
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

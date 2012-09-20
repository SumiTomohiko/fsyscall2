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
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/log.h>

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
		return (fsyscall_encode_int32(fd, dest, size));
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
execute_write(struct slave *slave, ssize_t *ret, int *errnum)
{
	int data_size, fd, len_fd, len_nbytes, nbytes, payload_size, rfd;
	char buf_fd[FSYSCALL_BUFSIZE_INT32], buf_nbytes[FSYSCALL_BUFSIZE_INT32];
	char *data;

	syslog(LOG_DEBUG, "Processing CMD_WRITE.");

	rfd = slave->rfd;
	payload_size = read_int32(rfd);
	len_fd = read_numeric_sequence(rfd, buf_fd, array_sizeof(buf_fd));
	fd = fsyscall_decode_int32(buf_fd, len_fd);
	len_nbytes = read_numeric_sequence(
		rfd,
		buf_nbytes,
		array_sizeof(buf_nbytes));
	nbytes = fsyscall_decode_int32(buf_nbytes, len_nbytes);

	syslog(LOG_DEBUG, "CMD_WRITE: fd=%d, nbytes=%d", fd, nbytes);

	data_size = payload_size - (len_fd + len_nbytes);
	data = (char *)alloca(sizeof(char) * data_size);
	read_or_die(rfd, data, data_size);
	*ret = write(fd, data, nbytes);
	*errnum = errno;
}

static void
return_write(struct slave *slave, ssize_t ret, int errnum)
{
	int errnum_len, ret_len, wfd;
	char errnum_buf[FSYSCALL_BUFSIZE_INT32];
	char ret_buf[FSYSCALL_BUFSIZE_INT64];

	ret_len = fsyscall_encode_int64(ret, ret_buf, array_sizeof(ret_buf));
	errnum_len = (ret != -1) ? fsyscall_encode_int32(
			errnum,
			errnum_buf,
			array_sizeof(errnum_buf)) : 0;

	wfd = slave->wfd;
	write_command(wfd, RET_WRITE);
	write_payload_size(wfd, ret_len + errnum_len);
	write_or_die(wfd, ret_buf, ret_len);
	write_or_die(wfd, errnum_buf, errnum_len);
}

static void
process_write(struct slave *slave)
{
	ssize_t ret;
	int errnum;

	execute_write(slave, &ret, &errnum);
	return_write(slave, ret, errnum);
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
		case CALL_EXIT:
			return (read_int32(rfd));
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

#include <sys/types.h>
#include <sys/event.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <fsyscall.h>
#include <fsyscall/private.h>
#include <fsyscall/private/atoi_or_die.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fork_or_die.h>
#include <fsyscall/private/fslave.h>
#include <fsyscall/private/fslave/proto.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/log.h>
#include <fsyscall/private/malloc_or_die.h>
#include <fsyscall/private/payload.h>
#include <fsyscall/private/read_sockaddr.h>
#include <fsyscall/private/select.h>

static int sigw;

static void
usage()
{
	puts("fslave rfd wfd fork_sock");
}

void
die_if_payload_size_mismatched(int expected, int actual)
{
	if (expected == actual)
		return;
	diec(-1, EPROTO, "payload size mismatched");
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
	if ((slave->sigr == fd) || (sigw == fd))
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
	write_command(wfd, SELECT_RETURN);
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
	write_command(wfd, SELECT_RETURN);
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
read_accept_protocol_request(struct slave *slave, int *s)
{
	payload_size_t actual_payload_size, payload_size;
	int namelen_len, rfd, s_len;

	rfd = slave->rfd;
	payload_size = read_payload_size(rfd);
	*s = read_int(rfd, &s_len);
	read_socklen(rfd, &namelen_len);	/* namelen. unused */
	actual_payload_size = s_len + namelen_len;
	die_if_payload_size_mismatched(payload_size, actual_payload_size);
}

static void
write_payloaded_command(struct slave *slave, command_t command,
			struct payload *payload)
{
	payload_size_t payload_size;
	int wfd;

	wfd = slave->wfd;
	payload_size = payload_get_size(payload);
	write_command(wfd, command);
	write_payload_size(wfd, payload_size);
	write_or_die(wfd, payload_get(payload), payload_size);
}

static void
write_accept_protocol_response(struct slave *slave, command_t return_command,
			       int retval, struct sockaddr *addr,
			       socklen_t namelen)
{
	struct payload *payload;

	payload = payload_create();
	payload_add_int(payload, retval);
	payload_add_socklen(payload, namelen);
	payload_add_sockaddr(payload, addr);

	write_payloaded_command(slave, return_command, payload);

	payload_dispose(payload);
}

typedef int (*accept_syscall)(int, struct sockaddr *, socklen_t *);

static void
process_accept_protocol(struct slave *slave, command_t call_command,
			command_t return_command, accept_syscall syscall)
{
	struct sockaddr_storage addr;
	struct sockaddr *paddr;
	socklen_t namelen;
	int retval, s;

	read_accept_protocol_request(slave, &s);
	paddr = (struct sockaddr *)&addr;
	namelen = sizeof(addr);
	retval = syscall(s, paddr, &namelen);
	if (retval == -1) {
		return_int(slave, return_command, retval, errno);
		return;
	}
	write_accept_protocol_response(slave, return_command, retval, paddr,
				       namelen);
}

static int
rs_read_socklen(struct rsopts *opts, socklen_t *socklen, int *len)
{
	struct slave *slave = (struct slave *)opts->rs_bonus;

	*socklen = read_socklen(slave->rfd, len);

	return (0);
}

static int
rs_read_uint8(struct rsopts *opts, uint8_t *n, int *len)
{
	struct slave *slave = (struct slave *)opts->rs_bonus;

	*n = read_uint8(slave->rfd, len);

	return (0);
}

static int
rs_read_uint64(struct rsopts *opts, uint64_t *n, int *len)
{
	struct slave *slave = (struct slave *)opts->rs_bonus;

	*n = read_uint64(slave->rfd, len);

	return (0);
}

static int
rs_read(struct rsopts *opts, char *buf, int len)
{
	struct slave *slave = (struct slave *)opts->rs_bonus;

	read_or_die(slave->rfd, buf, len);

	return (0);
}

static void *
rs_malloc(struct rsopts *opts, size_t size)
{

	return malloc(size);
}

static void
rs_free(struct rsopts *opts, void *ptr)
{

	free(ptr);
}

static void
read_sockaddr(struct slave *slave, struct sockaddr *addr, int *addrlen)
{
	struct rsopts opts;
	int error;

	opts.rs_bonus = slave;
	opts.rs_read_socklen = rs_read_socklen;
	opts.rs_read_uint8 = rs_read_uint8;
	opts.rs_read_uint64 = rs_read_uint64;
	opts.rs_read = rs_read;
	opts.rs_malloc = rs_malloc;
	opts.rs_free = rs_free;

	error = fsyscall_read_sockaddr(&opts, (struct sockaddr_storage *)addr,
				       addrlen);
	if (error != 0)
		die(1, "failed to read sockaddr");
}

typedef int (*connect_syscall)(int, const struct sockaddr *, socklen_t);

static void
process_connect_protocol(struct slave *slave, command_t call_command,
			 command_t return_command, connect_syscall syscall)
{
	struct sockaddr *name;
	payload_size_t actual_payload_size, payload_size;
	socklen_t namelen;
	int namelen_len, retval, rfd, s, s_len, sockaddr_len;

	rfd = slave->rfd;
	actual_payload_size = 0;
	payload_size = read_payload_size(rfd);

	s = read_int32(rfd, &s_len);
	actual_payload_size += s_len;

	namelen = read_uint32(rfd, &namelen_len);
	actual_payload_size += namelen_len;
	name = (struct sockaddr *)alloca(namelen);

	read_sockaddr(slave, name, &sockaddr_len);
	actual_payload_size += sockaddr_len;

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	retval = syscall(s, name, namelen);
	return_int(slave, return_command, retval, errno);
}

struct poll_args {
	struct pollfd *fds;
	nfds_t nfds;
	int timeout;
};

static void
read_poll_args(struct slave *slave, struct poll_args *dest, int nfdsopts)
{
	struct pollfd *fds;
	payload_size_t actual_payload_size, payload_size;
	int events_len, fd_len, i, nfds, nfds_len;
	int rfd, timeout, timeout_len;

	rfd = slave->rfd;
	payload_size = read_payload_size(rfd);
	actual_payload_size = 0;

	nfds = read_int32(rfd, &nfds_len);
	actual_payload_size += nfds_len;
	fds = (struct pollfd *)malloc(sizeof(*fds) * (nfds + nfdsopts));
	for (i = 0; i < nfds; i++) {
		fds[i].fd = read_int32(rfd, &fd_len);
		actual_payload_size += fd_len;
		fds[i].events = read_int16(rfd, &events_len);
		actual_payload_size += events_len;
		fds[i].revents = 0;
	}
	timeout = read_int32(rfd, &timeout_len);
	actual_payload_size += timeout_len;

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	dest->fds = fds;
	dest->nfds = nfds;
	dest->timeout = timeout;
}

static void
write_poll_result(struct slave *slave, command_t cmd, int retval, int e,
		  struct pollfd *fds, nfds_t nfds)
{
	payload_size_t return_payload_size;
	size_t rest_size;
	int i, retval_len, revents_len, wfd;
	char buf[256], *p;

	if ((retval == 0) || (retval == -1)) {
		return_int(slave, cmd, retval, e);
		return;
	}

	p = buf;
	rest_size = sizeof(buf);
	retval_len = encode_int32(retval, p, rest_size);
	p += retval_len;
	rest_size -= retval_len;
	for (i = 0; i < nfds; i++) {
		revents_len = encode_int16(fds[i].revents, p, rest_size);
		p += revents_len;
		rest_size -= revents_len;
	}
	return_payload_size = sizeof(buf) - rest_size;

	wfd = slave->wfd;
	write_command(wfd, cmd);
	write_payload_size(wfd, return_payload_size);
	write_or_die(wfd, buf, return_payload_size);
}

static void
process_poll(struct slave *slave)
{
	struct poll_args args;
	struct pollfd *fds;
	nfds_t nfds;
	int retval;

	read_poll_args(slave, &args, 0);

	fds = args.fds;
	nfds = args.nfds;
	retval = poll(fds, nfds, args.timeout);

	write_poll_result(slave, POLL_RETURN, retval, errno, fds, nfds);

	free(fds);
}

static void
process_poll_start(struct slave *slave)
{
	struct poll_args args;
	struct pollfd *fds, *shubfd;
	nfds_t nfds;
	command_t cmd;
	int n, retval;

	read_poll_args(slave, &args, 1);

	fds = args.fds;
	nfds = args.nfds;
	shubfd = &fds[nfds];
	shubfd->fd = slave->rfd;
	shubfd->events = POLLIN;
	shubfd->revents = 0;

	retval = poll(fds, nfds, INFTIM);

	n = (retval != -1) && ((shubfd->revents & POLLIN) != 0) ? 1 : 0;
	write_poll_result(slave, POLL_ENDED, retval - n, errno, fds, nfds);

	free(fds);

	cmd = read_command(slave->rfd);
	if (cmd != POLL_END)
		diex(1, "protocol error: %s (%d)", get_command_name(cmd), cmd);
}

static void
signal_handler(int sig)
{
	char c = (char)sig;

	write_or_die(sigw, &c, sizeof(c));
}

static int
initialize_signal_handling(struct slave *slave)
{
	int fds[2];

	if (pipe(fds) == -1)
		return (-1);
	slave->sigr = fds[0];
	sigw = fds[1];

	return (0);
}

static void
child_main(struct slave *slave, const char *token, size_t token_size,
	   pid_t parent, sigset_t *sigset)
{
	struct sockaddr_storage sockaddr;
	struct sockaddr_un *addr;
	int sock;
	const char *fmt = "A new child process has started: rfd=%d, wfd=%d";
	char len;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		die(1, "Cannot socket(2)");
	addr = (struct sockaddr_un *)&sockaddr;
	addr->sun_family = AF_LOCAL;
	strncpy(addr->sun_path, slave->fork_sock, sizeof(addr->sun_path));
	addr->sun_len = len = SUN_LEN(addr);
	if (connect(sock, (struct sockaddr *)addr, len) != 0)
		die(1, "Cannot connect(2)");

	write_or_die(sock, token, token_size);

	slave->rfd = slave->wfd = sock;
	if (close(slave->sigr) != 0)
		die(1, "Cannot close(2) for sigr");
	if (close(sigw) != 0)
		die(1, "Cannot close(2) for sigw");
	initialize_signal_handling(slave);
	if (sigprocmask(SIG_SETMASK, sigset, NULL) == -1)
		die(1, "sigprocmask(2) to recover failed");
	syslog(LOG_INFO, fmt, slave->rfd, slave->wfd);
}

static void
process_fork(struct slave *slave)
{
	sigset_t oset, set;
	payload_size_t len, payload_size;
	pid_t parent_pid, pid;
	int rfd, wfd;
	char buf[FSYSCALL_BUFSIZE_INT32], *token;

	rfd = slave->rfd;
	payload_size = read_payload_size(rfd);
	token = (char *)alloca(payload_size);
	read_or_die(rfd, token, payload_size);

	if (sigfillset(&set) == -1)
		die(1, "sigfillset(3) failed");
	if (sigprocmask(SIG_BLOCK, &set, &oset) == -1)
		die(1, "sigprocmask(2) to block all signals failed");

	parent_pid = getpid();
	pid = fork_or_die();
	if (pid == 0) {
		child_main(slave, token, payload_size, parent_pid, &oset);
		return;
	}
	syslog(LOG_DEBUG, "forked: pid=%d", pid);
	if (sigprocmask(SIG_SETMASK, &oset, NULL) == -1)
		die(1, "sigprocmask(2) to recover failed");

	len = encode_int32(pid, buf, sizeof(buf));
	wfd = slave->wfd;
	write_command(wfd, FORK_RETURN);
	write_payload_size(wfd, len);
	write_or_die(wfd, buf, len);
}

static void
process_kevent(struct slave *slave)
{
	struct kevent *changelist, *eventlist, *kev;
	struct payload *payload;
	struct timespec timeout, *ptimeout;
	payload_size_t actual_payload_size, payload_size;
	size_t size;
	command_t return_command;
	int changelist_code, i, kq, len, nchanges, nevents, retval, rfd;
	int timeout_code, udata_code;
	const char *fmt = "Invalid kevent(2) changelist code: %d";
	const char *fmt2 = "Invalid kevent(2) timeout code: %d";

	rfd = slave->rfd;
	payload_size = read_payload_size(rfd);

	kq = read_int(rfd, &len);
	actual_payload_size = len;

	nchanges = read_int(rfd, &len);
	actual_payload_size += len;

	changelist_code = read_int(rfd, &len);
	actual_payload_size += len;

	switch (changelist_code) {
	case KEVENT_CHANGELIST_NOT_NULL:
		size = sizeof(*changelist) * nchanges;
		changelist = (struct kevent *)alloca(size);
		for (i = 0; i < nchanges; i++) {
			kev = &changelist[i];
			kev->ident = read_ulong(rfd, &len);
			actual_payload_size += len;
			kev->filter = read_short(rfd, &len);
			actual_payload_size += len;
			kev->flags = read_ushort(rfd, &len);
			actual_payload_size += len;
			kev->fflags = read_uint(rfd, &len);
			actual_payload_size += len;
			kev->data = read_long(rfd, &len);
			actual_payload_size += len;
			udata_code = read_int(rfd, &len);
			actual_payload_size += len;
			switch (udata_code) {
			case KEVENT_UDATA_NULL:
				kev->udata = NULL;
				break;
			case KEVENT_UDATA_NOT_NULL:
			default:
				die(1, "Invalid udata code: %d", udata_code);
				break;
			}
		}
		break;
	case KEVENT_CHANGELIST_NULL:
		changelist = NULL;
		break;
	default:
		die(1, fmt, changelist_code);
		break;
	}

	nevents = read_int(rfd, &len);
	actual_payload_size += len;
	eventlist = (struct kevent *)alloca(sizeof(*eventlist) * nevents);

	timeout_code = read_int(rfd, &len);
	actual_payload_size += len;

	switch (timeout_code) {
	case KEVENT_TIMEOUT_NOT_NULL:
		timeout.tv_sec = read_int64(rfd, &len);
		actual_payload_size += len;
		timeout.tv_nsec = read_int64(rfd, &len);
		actual_payload_size += len;
		ptimeout = &timeout;
		break;
	case KEVENT_TIMEOUT_NULL:
		ptimeout = NULL;
		break;
	default:
		die(1, fmt2, timeout_code);
		break;
	}

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	retval = kevent(kq, changelist, nchanges, eventlist, nevents, ptimeout);
	syslog(LOG_DEBUG, "kevent: kq=%d, nchanges=%d, nevents=%d, retval=%d", kq, nchanges, nevents, retval);
	return_command = KEVENT_RETURN;
	if (retval == -1) {
		return_int(slave, return_command, retval, errno);
		return;
	}

	payload = payload_create();
	payload_add_int(payload, retval);
	for (i = 0; i < retval; i++)
		payload_add_kevent(payload, &eventlist[i]);
	write_payloaded_command(slave, return_command, payload);
	payload_dispose(payload);
}

static void
process_setsockopt(struct slave *slave)
{
	payload_size_t actual_payload_size, payload_size;
	socklen_t optlen;
	int level, level_len, n, optname, optname_len, optlen_len, optval_len;
	int retval, rfd, s, s_len;
	void *optval;

	rfd = slave->rfd;
	payload_size = read_payload_size(rfd);

	s = read_int32(rfd, &s_len);
	actual_payload_size = s_len;

	level = read_int32(rfd, &level_len);
	actual_payload_size += level_len;

	optname = read_int32(rfd, &optname_len);
	actual_payload_size += optname_len;

	optlen = read_socklen(rfd, &optlen_len);
	actual_payload_size += optlen_len;

	switch (optname) {
	case SO_REUSEADDR:
		n = read_int(rfd, &optval_len);
		actual_payload_size += optval_len;
		optval = &n;
		break;
	default:
		die(1, "Unsupported socket option specified: %s", optname);
		break;
	}

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	retval = setsockopt(s, level, optname, optval, optlen);

	return_int(slave, SETSOCKOPT_RETURN, retval, errno);
}

static void
process_getsockopt(struct slave *slave)
{
	struct payload *payload;
	payload_size_t actual_payload_size, payload_size;
	socklen_t optlen;
	int level, level_len, optname, optname_len, optlen_len, retval, rfd, s;
	int s_len;
	void *optval;

	rfd = slave->rfd;
	payload_size = read_payload_size(rfd);

	s = read_int32(rfd, &s_len);
	actual_payload_size = s_len;

	level = read_int32(rfd, &level_len);
	actual_payload_size += level_len;

	optname = read_int32(rfd, &optname_len);
	actual_payload_size += optname_len;

	optlen = read_socklen(rfd, &optlen_len);
	actual_payload_size += optlen_len;

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	optval = alloca(optlen);
	retval = getsockopt(s, level, optname, optval, &optlen);

	if (retval == -1) {
		return_int(slave, GETSOCKOPT_RETURN, retval, errno);
		return;
	}

	payload = payload_create();
	payload_add_int(payload, retval);

	switch (optname) {
	case SO_REUSEADDR:
		payload_add_socklen(payload, optlen);
		payload_add_int(payload, *((int *)optval));
		break;
	default:
		return_int(slave, GETSOCKOPT_RETURN, -1, ENOPROTOOPT);
		goto exit;
	}

	write_payloaded_command(slave, GETSOCKOPT_RETURN, payload);

exit:
	payload_dispose(payload);
}

static void
process_sigaction(struct slave *slave)
{
	struct sigaction act;
	payload_size_t actual_payload_size, payload_size;
	int actcode, actcode_len, bits_len, flags, flags_len, i, retval, rfd;
	int sig, sig_len;

	rfd = slave->rfd;
	payload_size = read_payload_size(rfd);

	sig = read_int32(rfd, &sig_len);
	actual_payload_size = sig_len;

	actcode = read_uint8(rfd, &actcode_len);
	actual_payload_size += actcode_len;

	flags = read_int32(rfd, &flags_len);
	actual_payload_size += flags_len;

	switch (actcode) {
	case SIGNAL_DEFAULT:
	case SIGNAL_IGNORE:
		flags |= SA_RESTART;
		break;
	case SIGNAL_ACTIVE:
		break;
	default:
		die(1, "invalid sigaction code (%d)", actcode);
	}
	act.sa_handler = signal_handler;
	act.sa_flags = flags & ~SA_SIGINFO;

	for (i = 0; i < _SIG_WORDS; i++) {
		act.sa_mask.__bits[i] = read_uint32(rfd, &bits_len);
		actual_payload_size += bits_len;
	}

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	retval = sigaction(sig, &act, NULL);

	return_int(slave, SIGACTION_RETURN, retval, errno);
}

static void
process_select(struct slave *slave)
{
	struct timeval *ptimeout, timeout;
	fd_set exceptfds, readfds, writefds;
	int nfds, retval;

	FD_ZERO(&exceptfds);
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	read_select_parameters(slave, &nfds, &readfds, &writefds, &exceptfds, &timeout, &ptimeout);

	retval = select(nfds, &readfds, &writefds, &exceptfds, ptimeout);

	switch (retval) {
	case -1:
		return_int(slave, SELECT_RETURN, retval, errno);
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

	status = read_int32(slave->rfd, &_);

	syslog(LOG_DEBUG, "EXIT_CALL: status=%d", status);

	return (status);
}

static void
process_signal(struct slave *slave)
{
	int n, wfd;
	char sig;

	read_or_die(slave->sigr, &sig, sizeof(sig));
	n = (int)sig;
	syslog(LOG_DEBUG, "signaled: %d (SIG%s)", n, sys_signame[n]);

	wfd = slave->wfd;
	write_command(wfd, SIGNALED);
	write_or_die(wfd, &sig, sizeof(sig));
}

static int
mainloop(struct slave *slave)
{
	fd_set fds, *pfds;
	command_t cmd;
	int nfds;
	const char *name;

	pfds = &fds;
	for (;;) {
		nfds = slave->rfd < slave->sigr ? slave->sigr : slave->rfd;
		FD_ZERO(pfds);
		FD_SET(slave->rfd, pfds);
		FD_SET(slave->sigr, pfds);
		if (select(nfds + 1, pfds, NULL, NULL, NULL) == -1) {
			if (errno != EINTR)
				die(1, "select(2) failed");
			continue;
		}

		if (FD_ISSET(slave->sigr, pfds))
			process_signal(slave);

		if (FD_ISSET(slave->rfd, pfds)) {
			cmd = read_command(slave->rfd);
			name = get_command_name(cmd);
			syslog(LOG_DEBUG, "processing %s.", name);
			switch (cmd) {
#include "dispatch.inc"
			case FORK_CALL:
				process_fork(slave);
				break;
			case SELECT_CALL:
				process_select(slave);
				break;
			case CONNECT_CALL:
				process_connect_protocol(slave, CONNECT_CALL,
							 CONNECT_RETURN,
							 connect);
				break;
			case BIND_CALL:
				process_connect_protocol(slave, BIND_CALL,
							 BIND_RETURN, bind);
				break;
			case GETPEERNAME_CALL:
				process_accept_protocol(slave, GETPEERNAME_CALL,
							GETPEERNAME_RETURN,
							getpeername);
				break;
			case GETSOCKNAME_CALL:
				process_accept_protocol(slave, GETSOCKNAME_CALL,
							GETSOCKNAME_RETURN,
							getsockname);
				break;
			case ACCEPT_CALL:
				process_accept_protocol(slave, ACCEPT_CALL,
							ACCEPT_RETURN, accept);
				break;
			case SIGACTION_CALL:
				process_sigaction(slave);
				break;
			case POLL_CALL:
				process_poll(slave);
				break;
			case GETSOCKOPT_CALL:
				process_getsockopt(slave);
				break;
			case SETSOCKOPT_CALL:
				process_setsockopt(slave);
				break;
			case KEVENT_CALL:
				process_kevent(slave);
				break;
			case POLL_START:
				process_poll_start(slave);
				break;
			case EXIT_CALL:
				return process_exit(slave);
			default:
				diex(-1, "unknown command (%d)", cmd);
				/* NOTREACHED */
			}
		}
	}

	return (-1);
}

static int
slave_main(struct slave *slave)
{
	negotiate_version(slave);
	//write_pid(slave->wfd, getpid());
	write_open_fds(slave);

	return (mainloop(slave));
}

static int
initialize_sigaction()
{
	struct sigaction act;
	int i, nsigs, sig;
	int sigs[] = { SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
		       SIGEMT, SIGFPE, SIGBUS, /*SIGSEGV,*/ SIGSYS, SIGPIPE,
		       SIGALRM, SIGTERM, SIGURG, SIGTSTP, SIGCONT, SIGCHLD,
		       SIGTTIN, SIGTTOU, SIGIO, SIGXCPU, SIGXFSZ, SIGVTALRM,
		       SIGPROF, SIGWINCH, SIGINFO, SIGUSR1, SIGUSR2, SIGTHR };
	const char *fmt = "cannot sigaction(2) for %d (SIG%s)";

	act.sa_handler = signal_handler;
	act.sa_flags = SA_RESTART;
	if (sigfillset(&act.sa_mask) == -1)
		die(1, "cannot sigemptyset(3)");

	nsigs = array_sizeof(sigs);
	for (i = 0; i < nsigs; i++) {
		sig = sigs[i];
		if (sigaction(sig, &act, NULL) == -1)
			die(1, fmt, sig, sys_signame[sig]);
	}

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
	int opt, status;
	char **args;

	openlog(argv[0], LOG_PID, LOG_USER);
	log_start_message(argc, argv);

	while ((opt = getopt_long(argc, argv, "+", opts, NULL)) != -1)
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
	if (initialize_signal_handling(&slave) != 0)
		return (3);
	if (initialize_sigaction() != 0)
		return (4);
	slave.fork_sock = args[2];

	status = slave_main(&slave);
	log_graceful_exit(status);

	return (status);
}

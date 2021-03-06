#include <sys/types.h>
#include <sys/event.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <assert.h>
#include <dirent.h>
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
#include <zlib.h>
#if 0
#include <md5.h>
#endif

#include <fsyscall.h>
#include <fsyscall/private.h>
#include <fsyscall/private/atoi_or_die.h>
#include <fsyscall/private/close_or_die.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fork_or_die.h>
#include <fsyscall/private/fslave.h>
#include <fsyscall/private/fslave/dir_entries_cache.h>
#include <fsyscall/private/fslave/proto.h>
#include <fsyscall/private/fslave/stream.h>
#include <fsyscall/private/geterrorname.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/io_or_die.h>
#include <fsyscall/private/log.h>
#include <fsyscall/private/malloc_or_die.h>
#include <fsyscall/private/payload.h>
#include <fsyscall/private/read_sockaddr.h>
#include <fsyscall/private/select.h>

struct memory {
	SLIST_ENTRY(memory)	mem_next;
	char			mem_data[0];
};

static int	mainloop(struct slave_thread *);

static int sigs[] = { SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGEMT,
		      SIGFPE, SIGBUS, /*SIGSEGV,*/ SIGSYS, SIGPIPE, SIGALRM,
		      SIGTERM, SIGURG, SIGTSTP, SIGCONT, SIGCHLD, SIGTTIN,
		      SIGTTOU, SIGIO, SIGXCPU, SIGXFSZ, SIGVTALRM, SIGPROF,
		      SIGWINCH, SIGINFO, SIGUSR1, SIGUSR2, /*SIGTHR*/ };
static int nsigs = array_sizeof(sigs);

static struct io	sigw;

#if 0
static void
sighandler(int sig)
{

	syslog(LOG_DEBUG, "signaled (default): SIG%s", sys_signame[sig]);
}
#endif

static void
reset_signal_handler()
{
	struct sigaction act;
	int i;

	act.sa_handler = SIG_DFL;
#if 0
	act.sa_handler = sighandler;
#endif
	act.sa_flags = 0;
	sigfillset(&act.sa_mask);
	for (i = 0; i < nsigs; i++)
		sigaction(sigs[i], &act, NULL);
}

static void
destroy_slave(struct slave *slave)
{

	free(slave->fork_sock);
	reset_signal_handler();
	if (io_close(&sigw) == -1)
		diec(1, sigw.io_error, "cannot close sigw");
	if (io_close(&slave->fsla_sigr) == -1)
		diec(1, slave->fsla_sigr.io_error, "cannot close sigr");
	dir_entries_cache_dispose(slave->fsla_dir_entries_cache);
	pthread_rwlock_destroy(&slave->fsla_lock);
	free(slave);
}

static void
unlock_slave(struct slave *slave)
{
	int error;

	error = pthread_rwlock_unlock(&slave->fsla_lock);
	if (error != 0)
		diex(error, "cannot pthread_rwlock_unlock(3)");
}

static void
readlock_slave(struct slave *slave)
{
	int error;

	error = pthread_rwlock_rdlock(&slave->fsla_lock);
	if (error != 0)
		diex(error, "cannot pthread_rwlock_rdlock(3)");
}

static void
writelock_slave(struct slave *slave)
{
	int error;

	error = pthread_rwlock_wrlock(&slave->fsla_lock);
	if (error != 0)
		diex(error, "cannot pthread_rwlock_wrlock(3)");
}

static void
close_slave_thread(struct slave_thread *slave_thread)
{
	struct io *io;

	io = &slave_thread->fsth_io;
	if (io_close(io) == -1)
		diec(1, io->io_error, "cannot close slave thread");
}

static void
release_slave_thread(struct slave_thread *slave_thread)
{
	struct slave *slave;
	bool empty;

	close_slave_thread(slave_thread);

	slave = slave_thread->fsth_slave;
	writelock_slave(slave);
	SLIST_REMOVE(&slave->fsla_slaves, slave_thread, slave_thread,
		     fsth_next);
	empty = SLIST_EMPTY(&slave->fsla_slaves);
	unlock_slave(slave);

	free(slave_thread);
	if (empty)
		destroy_slave(slave);
}

static void *
mem_alloc(struct slave_thread *slave_thread, size_t size)
{
	struct memory *memory;
	size_t totalsize;

	totalsize = sizeof(struct memory) + size;
	memory = (struct memory *)malloc_or_die(totalsize);
	SLIST_INSERT_HEAD(&slave_thread->fsth_memory, memory, mem_next);

	return (&memory->mem_data[0]);
}

static void
mem_freeall(struct slave_thread *slave_thread)
{
	struct memory *memory, *tmp;

	SLIST_FOREACH_SAFE(memory, &slave_thread->fsth_memory, mem_next, tmp) {
		SLIST_REMOVE(&slave_thread->fsth_memory, memory, memory,
			     mem_next);
		free(memory);
	}
}

static void
process_signal(struct slave_thread *slave_thread)
{
	struct io *dst;
	int n;
	char sig;

	read_or_die(&slave_thread->fsth_slave->fsla_sigr, &sig, sizeof(sig));
	n = (int)sig;
	syslog(LOG_DEBUG, "signaled: %d (SIG%s)", n, sys_signame[n]);

	dst = &slave_thread->fsth_io;
	write_command(dst, SIGNALED);
	write_or_die(dst, &sig, sizeof(sig));
}

void
suspend_signal(struct slave_thread *slave_thread, sigset_t *oset)
{
	struct slave *slave;

	slave = slave_thread->fsth_slave;
	readlock_slave(slave);
	if (sigprocmask(SIG_SETMASK, &slave->mask, oset) == -1)
		die(1, "failed sigprocmask(2) to suspend signal");
	unlock_slave(slave);
}

void
resume_signal(struct slave_thread *slave_thread, sigset_t *set)
{
	struct io *ios[1];
	struct timeval timeout;
	int error, n;

	if (sigprocmask(SIG_SETMASK, set, NULL) == -1)
		die(1, "failed sigprocmask(2) to resume signal");
	if (!slave_thread->fsth_signal_watcher)
		return;

	ios[0] = &slave_thread->fsth_slave->fsla_sigr;
	timeout.tv_sec = timeout.tv_usec = 0;
	for (;;) {
		n = io_select(array_sizeof(ios), ios, &timeout, &error);
		if (n == -1) {
			if (error != EINTR)
				die(1, "failed select(2)");
			continue;
		}
		if (n == 0)
			return;
		process_signal(slave_thread);
	}
}

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
negotiate_version(struct slave_thread *slave_thread)
{
	uint8_t request_ver = 0;
	uint8_t response;

	write_or_die(&slave_thread->fsth_io, &request_ver, sizeof(request_ver));
	read_or_die(&slave_thread->fsth_io, &response, sizeof(response));
	assert(response == 0);
	syslog(LOG_INFO, "protocol version for shub is %d.", response);
}

static bool
is_alive_fd(struct slave_thread *slave_thread, int fd)
{
	if (io_get_rfd(&slave_thread->fsth_io) == fd)
		return (false);
	if (io_get_wfd(&slave_thread->fsth_io) == fd)
		return (false);
	if (io_get_rfd(&slave_thread->fsth_slave->fsla_sigr) == fd)
		return (false);
	if (io_get_wfd(&sigw) == fd)
		return (false);
	if (fcntl(fd, F_GETFL) != -1)
		return (true);
	if (errno != EBADF)
		die(-1, "cannot fcntl(%d, F_GETFL)", fd);
	return (false);
}

static int
count_alive_fds(struct slave_thread *slave_thread)
{
	int i, n = 0, size;

	size = getdtablesize();
	for (i = 0; i < size; i++)
		n += is_alive_fd(slave_thread, i) ? 1 : 0;

	return (n);
}

static int
encode_alive_fd(struct slave_thread *slave_thread, int fd, char *dest, int size)
{
	if (is_alive_fd(slave_thread, fd))
		return (encode_int32(fd, dest, size));
	return (0);
}

static void
write_open_fds(struct slave_thread *slave_thread)
{
	struct io *io;
	size_t buf_size;
	int i, nfds, pos;
	char *buf;

	buf_size = count_alive_fds(slave_thread) * FSYSCALL_BUFSIZE_INT32;
	buf = (char *)alloca(buf_size);

	pos = 0;
	nfds = getdtablesize();
	for (i = 0; i < nfds; i++)
		pos += encode_alive_fd(slave_thread, i, buf + pos,
				       buf_size - pos);

	assert(0 <= pos);
	io = &slave_thread->fsth_io;
	write_int32(io, pos);
	write_or_die(io, buf, pos);
}

static void
return_generic(struct slave_thread *slave_thread, command_t cmd, char *ret_buf,
	       int ret_len, char *errnum_buf, int errnum_len)
{
	struct io *io;

	io = &slave_thread->fsth_io;
	write_command(io, cmd);
	write_payload_size(io, ret_len + errnum_len);
	write_or_die(io, ret_buf, ret_len);
	write_or_die(io, errnum_buf, errnum_len);
}

void
return_int(struct slave_thread *slave_thread, command_t cmd, int ret,
	   int errnum)
{
	int errnum_len, ret_len;
	char errnum_buf[FSYSCALL_BUFSIZE_INT32];
	char ret_buf[FSYSCALL_BUFSIZE_INT32];
	const char *cmdname, *errname, *fmt = "%s: ret=%d, error=%d (%s: %s)";

	cmdname = get_command_name(cmd);
	errname = geterrorname(errnum);
	syslog(LOG_DEBUG, fmt, cmdname, ret, errnum, errname, strerror(errnum));

	ret_len = encode_int32(ret, ret_buf, array_sizeof(ret_buf));
	errnum_len = (ret == -1) ? encode_int32(
			errnum,
			errnum_buf,
			array_sizeof(errnum_buf)) : 0;

	return_generic(slave_thread, cmd, ret_buf, ret_len, errnum_buf,
		       errnum_len);
}

void
return_ssize(struct slave_thread *slave_thread, command_t cmd, ssize_t ret,
	     int errnum)
{
	int errnum_len, ret_len;
	char errnum_buf[FSYSCALL_BUFSIZE_INT32];
	char ret_buf[FSYSCALL_BUFSIZE_INT64];
	const char *cmdname, *errname, *fmt = "%s: ret=%zd, error=%d (%s: %s)";

	cmdname = get_command_name(cmd);
	errname = geterrorname(errnum);
	syslog(LOG_DEBUG, fmt, cmdname, ret, errnum, errname, strerror(errnum));

	ret_len = encode_int64(ret, ret_buf, array_sizeof(ret_buf));
	errnum_len = (ret == -1) ? encode_int32(
			errnum,
			errnum_buf,
			array_sizeof(errnum_buf)) : 0;

	return_generic(slave_thread, cmd, ret_buf, ret_len, errnum_buf,
		       errnum_len);
}

#define	MAX(a, b)	((a) < (b) ? (b) : (a))

static void
read_fds(struct slave_thread *slave_thread, int *maxfd, fd_set *fds,
	 payload_size_t *len)
{
	struct io *io;
	payload_size_t fd_len, nfds_len, payload_size;
	int fd, i, nfds;

	io = &slave_thread->fsth_io;

	nfds = read_int32(io, &nfds_len);
	payload_size = nfds_len;

	for (i = 0; i < nfds; i++) {
		fd = read_int32(io, &fd_len);
		payload_size += fd_len;
		FD_SET(fd, fds);
		*maxfd = MAX(*maxfd, fd);
	}

	*len = payload_size;
}

static void
read_select_parameters(struct slave_thread *slave_thread, int *nfds,
		       fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		       struct timeval *timeout, struct timeval **ptimeout)
{
	struct io *io;
	payload_size_t actual_payload_size, exceptfds_len, payload_size;
	payload_size_t readfds_len, timeout_len, timeout_status_len;
	payload_size_t writefds_len;
	int maxfd, timeout_status;

	io = &slave_thread->fsth_io;
	actual_payload_size = 0;
	payload_size = read_payload_size(io);

	maxfd = 0;
	read_fds(slave_thread, &maxfd, readfds, &readfds_len);
	actual_payload_size += readfds_len;
	read_fds(slave_thread, &maxfd, writefds, &writefds_len);
	actual_payload_size += writefds_len;
	read_fds(slave_thread, &maxfd, exceptfds, &exceptfds_len);
	actual_payload_size += exceptfds_len;

	timeout_status = read_int32(io, &timeout_status_len);
	actual_payload_size += timeout_status_len;

	if (timeout_status == 0)
		*ptimeout = NULL;
	else {
		assert(timeout_status == 1);
		read_timeval(io, timeout, &timeout_len);
		actual_payload_size += timeout_len;
		*ptimeout = timeout;
	}

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	*nfds = maxfd + 1;
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
write_select_timeout(struct slave_thread *slave_thread)
{
	struct io *io;
	payload_size_t retval_len;
	char retval_buf[FSYSCALL_BUFSIZE_INT32];

	retval_len = fsyscall_encode_int32(0, retval_buf, sizeof(retval_buf));

	io = &slave_thread->fsth_io;
	write_command(io, SELECT_RETURN);
	write_payload_size(io, retval_len);
	write_or_die(io, retval_buf, retval_len);
}

static void
write_select_ready(struct slave_thread *slave_thread, int retval, int nfds,
		   fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
	struct io *io;
	payload_size_t exceptfds_len, nexceptfds_len, nreadfds_len;
	payload_size_t nwritefds_len, payload_size, readfds_len, retval_len;
	payload_size_t writefds_len;
	size_t exceptfds_buf_len, readfds_buf_len, writefds_buf_len;
	int nexceptfds, nreadfds, nwritefds;
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

	io = &slave_thread->fsth_io;
	payload_size = retval_len + nreadfds_len + readfds_len + nwritefds_len +
		       writefds_len + nexceptfds_len + exceptfds_len;
	write_command(io, SELECT_RETURN);
	write_payload_size(io, payload_size);
	write_or_die(io, retval_buf, retval_len);
	write_or_die(io, nreadfds_buf, nreadfds_len);
	write_or_die(io, readfds_buf, readfds_len);
	write_or_die(io, nwritefds_buf, nwritefds_len);
	write_or_die(io, writefds_buf, writefds_len);
	write_or_die(io, nexceptfds_buf, nexceptfds_len);
	write_or_die(io, exceptfds_buf, exceptfds_len);
}

static void
read_accept_protocol_request(struct slave_thread *slave_thread, int *s)
{
	struct io *io;
	payload_size_t actual_payload_size, namelen_len, payload_size, s_len;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);
	*s = read_int(io, &s_len);
	read_socklen(io, &namelen_len);		/* namelen. unused */
	actual_payload_size = s_len + namelen_len;
	die_if_payload_size_mismatched(payload_size, actual_payload_size);
}

static void
write_payloaded_command(struct slave_thread *slave_thread, command_t command,
			struct payload *payload)
{
	struct io *io;
	payload_size_t payload_size;

	io = &slave_thread->fsth_io;
	payload_size = payload_get_size(payload);
	write_command(io, command);
	write_payload_size(io, payload_size);
	write_or_die(io, payload_get(payload), payload_size);
}

static void
write_accept_protocol_response(struct slave_thread *slave_thread,
			       command_t return_command, int retval,
			       struct sockaddr *addr, socklen_t namelen)
{
	struct payload *payload;

	payload = payload_create();
	payload_add_int(payload, retval);
	payload_add_socklen(payload, namelen);
	payload_add_sockaddr(payload, addr);

	write_payloaded_command(slave_thread, return_command, payload);

	payload_dispose(payload);
}

static void
read_accept4_args(struct slave_thread *slave_thread, int *s, int *flags)
{
	struct io *io;
	payload_size_t actual_payload_size, flags_len, namelen_len;
	payload_size_t payload_size, s_len;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);
	*s = read_int(io, &s_len);
	read_socklen(io, &namelen_len);		/* namelen. unused */
	*flags = read_int(io, &flags_len);
	actual_payload_size = s_len + namelen_len + flags_len;
	die_if_payload_size_mismatched(payload_size, actual_payload_size);
}

static void
process_accept4(struct slave_thread *slave_thread)
{
	struct sockaddr_storage addr;
	struct sockaddr *paddr;
	sigset_t oset;
	socklen_t namelen;
	command_t return_command;
	int e, flags, retval, s;

	read_accept4_args(slave_thread, &s, &flags);

	paddr = (struct sockaddr *)&addr;
	namelen = sizeof(addr);
	suspend_signal(slave_thread, &oset);
	retval = accept4(s, paddr, &namelen, flags);
	e = errno;
	resume_signal(slave_thread, &oset);

	return_command = ACCEPT4_RETURN;
	if (retval == -1) {
		return_int(slave_thread, return_command, retval, e);
		return;
	}
	write_accept_protocol_response(slave_thread, return_command, retval,
				       paddr, namelen);
}

typedef int (*accept_syscall)(int, struct sockaddr *, socklen_t *);

static void
process_accept_protocol(struct slave_thread *slave_thread,
			command_t call_command, command_t return_command,
			accept_syscall syscall)
{
	struct sockaddr_storage addr;
	struct sockaddr *paddr;
	sigset_t oset;
	socklen_t namelen;
	int e, retval, s;

	read_accept_protocol_request(slave_thread, &s);
	paddr = (struct sockaddr *)&addr;
	namelen = sizeof(addr);
	suspend_signal(slave_thread, &oset);
	retval = syscall(s, paddr, &namelen);
	e = errno;
	resume_signal(slave_thread, &oset);
	if (retval == -1) {
		return_int(slave_thread, return_command, retval, e);
		return;
	}
	write_accept_protocol_response(slave_thread, return_command, retval,
				       paddr, namelen);
}

static int
rs_read_socklen(struct rsopts *opts, socklen_t *socklen, payload_size_t *len)
{
	struct slave_thread *slave_thread;

	slave_thread = (struct slave_thread *)opts->rs_bonus;

	*socklen = read_socklen(&slave_thread->fsth_io, len);

	return (0);
}

static int
rs_read_uint8(struct rsopts *opts, uint8_t *n, payload_size_t *len)
{
	struct slave_thread *slave_thread;

	slave_thread = (struct slave_thread *)opts->rs_bonus;

	*n = read_uint8(&slave_thread->fsth_io, len);

	return (0);
}

static int
rs_read_uint64(struct rsopts *opts, uint64_t *n, payload_size_t *len)
{
	struct slave_thread *slave_thread;

	slave_thread = (struct slave_thread *)opts->rs_bonus;

	*n = read_uint64(&slave_thread->fsth_io, len);

	return (0);
}

static int
rs_read(struct rsopts *opts, char *buf, int len)
{
	struct slave_thread *slave_thread;

	slave_thread = (struct slave_thread *)opts->rs_bonus;

	read_or_die(&slave_thread->fsth_io, buf, len);

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
read_sockaddr(struct slave_thread *slave_thread, struct sockaddr *addr,
	      payload_size_t *addrlen)
{
	struct rsopts opts;
	int error;

	opts.rs_bonus = slave_thread;
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
process_connect_protocol(struct slave_thread *slave_thread,
			 command_t call_command, command_t return_command,
			 connect_syscall syscall)
{
	struct io *io;
	struct sockaddr *name;
	sigset_t oset;
	payload_size_t actual_payload_size, namelen_len, payload_size, s_len;
	payload_size_t sockaddr_len;
	socklen_t namelen;
	int e, retval, s;

	io = &slave_thread->fsth_io;
	actual_payload_size = 0;
	payload_size = read_payload_size(io);

	s = read_int32(io, &s_len);
	actual_payload_size += s_len;

	namelen = read_uint32(io, &namelen_len);
	actual_payload_size += namelen_len;
	name = (struct sockaddr *)alloca(namelen);

	read_sockaddr(slave_thread, name, &sockaddr_len);
	actual_payload_size += sockaddr_len;

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	suspend_signal(slave_thread, &oset);
	retval = syscall(s, name, namelen);
	e = errno;
	resume_signal(slave_thread, &oset);

	return_int(slave_thread, return_command, retval, e);
}

struct poll_args {
	struct pollfd *fds;
	nfds_t nfds;
	int timeout;
};

static void
read_poll_args(struct slave_thread *slave_thread, struct poll_args *dest,
	       int nfdsopts)
{
	struct io *io;
	struct pollfd *fds;
	payload_size_t actual_payload_size, events_len, fd_len, nfds_len;
	payload_size_t payload_size, timeout_len;
	int i, nfds, timeout;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);
	actual_payload_size = 0;

	nfds = read_int32(io, &nfds_len);
	actual_payload_size += nfds_len;
	fds = (struct pollfd *)malloc(sizeof(*fds) * (nfds + nfdsopts));
	for (i = 0; i < nfds; i++) {
		fds[i].fd = read_int32(io, &fd_len);
		actual_payload_size += fd_len;
		fds[i].events = read_int16(io, &events_len);
		actual_payload_size += events_len;
		fds[i].revents = 0;
	}
	timeout = read_int32(io, &timeout_len);
	actual_payload_size += timeout_len;

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	dest->fds = fds;
	dest->nfds = nfds;
	dest->timeout = timeout;
}

static void
write_poll_result(struct slave_thread *slave_thread, command_t cmd, int retval,
		  int e, struct pollfd *fds, nfds_t nfds)
{
	struct io *io;
	payload_size_t return_payload_size;
	size_t rest_size;
	int i, retval_len, revents_len;
	char buf[256], *p;

	if ((retval == 0) || (retval == -1)) {
		return_int(slave_thread, cmd, retval, e);
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

	io = &slave_thread->fsth_io;
	write_command(io, cmd);
	write_payload_size(io, return_payload_size);
	write_or_die(io, buf, return_payload_size);
}

static void
process_poll(struct slave_thread *slave_thread)
{
	struct poll_args args;
	struct pollfd *fds;
	sigset_t oset;
	nfds_t nfds;
	int e, retval;

	read_poll_args(slave_thread, &args, 0);

	fds = args.fds;
	nfds = args.nfds;
	suspend_signal(slave_thread, &oset);
	retval = poll(fds, nfds, args.timeout);
	e = errno;
	resume_signal(slave_thread, &oset);

	write_poll_result(slave_thread, POLL_RETURN, retval, e, fds, nfds);

	free(fds);
}

static void
process_poll_start(struct slave_thread *slave_thread)
{
	struct poll_args args;
	struct pollfd *fds, *shubfd;
	sigset_t oset;
	nfds_t nfds;
	command_t cmd;
	int e, n, retval;

	read_poll_args(slave_thread, &args, 1);

	fds = args.fds;
	nfds = args.nfds;
	shubfd = &fds[nfds];
	shubfd->fd = io_get_rfd(&slave_thread->fsth_io);
	shubfd->events = POLLIN;
	shubfd->revents = 0;

	suspend_signal(slave_thread, &oset);
	retval = poll(fds, nfds + 1, INFTIM);
	e = errno;
	resume_signal(slave_thread, &oset);

	n = (retval != -1) && ((shubfd->revents & POLLIN) != 0) ? 1 : 0;
	write_poll_result(slave_thread, POLL_ENDED, retval - n, e, fds, nfds);

	free(fds);

	cmd = read_command(&slave_thread->fsth_io);
	if (cmd != POLL_END)
		diex(1, "protocol error: %s (%d)", get_command_name(cmd), cmd);
}

static void
merge_sigset(struct slave *slave, sigset_t *set, int (*f)(sigset_t *, int),
	     int *retval, int *errnum)
{
	int i, sig;

	for (i = 0; i < nsigs; i++) {
		sig = sigs[i];
		if (sigismember(set, sig))
			if (f(&slave->mask, sig) == -1) {
				*retval = -1;
				*errnum = errno;
				return;
			}
	}

	*retval = 0;
}

static void
drop_payload_to_error(struct slave_thread *slave_thread, command_t cmd,
		      payload_size_t len, int e)
{
	char *buf;

	buf = (char *)alloca(len);
	read_or_die(&slave_thread->fsth_io, buf, len);
	return_int(slave_thread, cmd, -1, e);
}

static int
read_recvmsg_args(struct slave_thread *slave_thread, int *fd,
		  struct msghdr *msg, int *flags)
{
	struct io *io;
	struct iovec *iov, *piov;
	payload_size_t actual_payload_size, controllen_len, fd_len, flags_len;
	payload_size_t iovlen_len, len_len, msg_flags_len, namecode_len;
	payload_size_t payload_size, rest_size;
	socklen_t controllen;
	command_t return_command;
	int i, iovlen, len, namecode;

	return_command = RECVMSG_RETURN;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);

	*fd = read_int(io, &fd_len);
	actual_payload_size = fd_len;

	namecode = read_int(io, &namecode_len);
	actual_payload_size += namecode_len;
	switch (namecode) {
	case MSGHDR_MSG_NAME_NOT_NULL:
		rest_size = payload_size - actual_payload_size;
		drop_payload_to_error(slave_thread, return_command, rest_size,
				      EOPNOTSUPP);
		return (-1);
	case MSGHDR_MSG_NAME_NULL:
		break;
	default:
		rest_size = payload_size - actual_payload_size;
		drop_payload_to_error(slave_thread, return_command, rest_size,
				      EINVAL);
		return (-1);
	}
	msg->msg_name = NULL;
	msg->msg_namelen = 0;

	iovlen = read_int(io, &iovlen_len);
	actual_payload_size += iovlen_len;
	iov = (struct iovec *)mem_alloc(slave_thread, sizeof(*iov) * iovlen);
	for (i = 0; i < iovlen; i++) {
		piov = &iov[i];
		len = read_int(io, &len_len);
		actual_payload_size += len_len;

		piov->iov_base = (char *)mem_alloc(slave_thread, len);
		piov->iov_len = len;
	}
	msg->msg_iov = iov;
	msg->msg_iovlen = iovlen;

	controllen = read_socklen(io, &controllen_len);
	actual_payload_size += controllen_len;
	msg->msg_control = 0 < controllen ? mem_alloc(slave_thread, controllen)
					  : NULL;
	msg->msg_controllen = controllen;

	msg->msg_flags = read_int(io, &msg_flags_len);
	actual_payload_size += msg_flags_len;

	*flags = read_int(io, &flags_len);
	actual_payload_size += flags_len;

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	return (0);
}

#define	MIN(a, b)	((a) < (b) ? (a) : (b))

static int
count_cmsghdrs(struct msghdr *msg)
{
	struct cmsghdr *cmsghdr;
	int n;

	n = 0;
	for (cmsghdr = CMSG_FIRSTHDR(msg);
	     cmsghdr != NULL;
	     cmsghdr = CMSG_NXTHDR(msg, cmsghdr))
		n++;

	return (n);
}

static void
add_control_size_info_to_payload(struct payload *payload, struct msghdr *msg)
{
	struct cmsghdr *cmsghdr;
	uintptr_t delta;
	int level, type;
	char *p, *pend;

	for (cmsghdr = CMSG_FIRSTHDR(msg);
	     cmsghdr != NULL;
	     cmsghdr = CMSG_NXTHDR(msg, cmsghdr)) {
		level = cmsghdr->cmsg_level;
		type = cmsghdr->cmsg_type;
		payload_add_int(payload, level);
		payload_add_int(payload, type);
		switch (level) {
		case SOL_SOCKET:
			switch (type) {
			case SCM_CREDS:
				/* nothing */
				break;
			case SCM_RIGHTS:
				p = (char *)CMSG_DATA(cmsghdr);
				pend = (char *)cmsghdr + cmsghdr->cmsg_len;
				delta = (uintptr_t)pend - (uintptr_t)p;
				payload_add_int(payload, delta / sizeof(int));
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
	}
}

static void
add_passed_fds_to_payload(struct payload *payload, struct cmsghdr *cmsghdr)
{
	int *pfd;
	char *p, *pend;

	assert(cmsghdr->cmsg_level == SOL_SOCKET);
	assert(cmsghdr->cmsg_type == SCM_RIGHTS);

	p = (char *)CMSG_DATA(cmsghdr);
	pend = (char *)cmsghdr + cmsghdr->cmsg_len;
	for (pfd = (int *)p; pfd != (int *)pend; pfd++)
		payload_add_int(payload, *pfd);
}

static void
write_recvmsg_result(struct slave_thread *slave_thread, ssize_t retval, int e,
		     struct msghdr *msg)
{
	struct msghdr *control;
	struct cmsghdr *cmsghdr;
	struct cmsgcred *cred;
	struct payload *payload;
	struct iovec *iov, *piov;
	size_t len;
	ssize_t rest;
	command_t return_command;
	gid_t *groups;
	int i, ncmsghdr;
	short ngroups;
	void *data;

	return_command = RECVMSG_RETURN;

	if (retval == -1) {
		return_ssize(slave_thread, return_command, retval, e);
		return;
	}

	payload = payload_create();
	payload_add_ssize(payload, retval);

	iov = msg->msg_iov;
	for (i = 0, rest = retval; 0 < rest; i++, rest -= len) {
		piov = &iov[i];
		len = MIN(piov->iov_len, rest);
		payload_add(payload, piov->iov_base, len);
	}

	control = (struct msghdr *)msg->msg_control;
	if (control != NULL) {
		ncmsghdr = count_cmsghdrs(msg);
		payload_add_int(payload, ncmsghdr);

		add_control_size_info_to_payload(payload, msg);

		for (cmsghdr = CMSG_FIRSTHDR(msg);
		     cmsghdr != NULL;
		     cmsghdr = CMSG_NXTHDR(msg, cmsghdr)) {
			data = CMSG_DATA(cmsghdr);
			switch (cmsghdr->cmsg_level) {
			case SOL_SOCKET:
				switch (cmsghdr->cmsg_type) {
				case SCM_CREDS:
					cred = (struct cmsgcred *)data;
					payload_add_pid(payload,
							cred->cmcred_pid);
					payload_add_uid(payload,
							cred->cmcred_uid);
					payload_add_uid(payload,
							cred->cmcred_euid);
					payload_add_gid(payload,
							cred->cmcred_gid);
					ngroups = cred->cmcred_ngroups;
					payload_add_short(payload, ngroups);
					groups = cred->cmcred_groups;
					for (i = 0; i < ngroups; i++)
						payload_add_gid(payload,
								groups[i]);
					break;
				case SCM_RIGHTS:
					add_passed_fds_to_payload(payload,
								  cmsghdr);
					break;
				default:
					break;
				}
				break;
			default:
				break;
			}
		}
	}

	write_payloaded_command(slave_thread, return_command, payload);

	payload_dispose(payload);
}

static void
process_recvmsg(struct slave_thread *slave_thread)
{
	struct msghdr msg;
	sigset_t oset;
	ssize_t retval;
	int e, error, fd, flags;

	error = read_recvmsg_args(slave_thread, &fd, &msg, &flags);
	if (error != 0)
		return;

	suspend_signal(slave_thread, &oset);
	retval = recvmsg(fd, &msg, flags);
	e = errno;
	resume_signal(slave_thread, &oset);

	write_recvmsg_result(slave_thread, retval, e, &msg);
}

static int
read_cmsghdrs(struct slave_thread *slave_thread, struct cmsghdr **control,
	      socklen_t *controllen, payload_size_t *actual_payload_size)
{
	struct cmsgspec {
		int		cmsgspec_level;
		int		cmsgspec_type;
		socklen_t	cmsgspec_len;
		socklen_t	cmsgspec_space;
		int		cmsgspec_nfds;		/* for SCM_RIGHTS */
	};

	struct cmsghdr *cmsghdr, *cmsghdrs;
	struct cmsgspec *spec, *specs;
	struct io *io;
	payload_size_t fd_len, level_len, ncmsghdr_len, nfds_len, payload_size;
	payload_size_t type_len;
	size_t cmsgspace, datasize;
	socklen_t len;
	int i, j, level, ncmsghdr, nfds, *pfd, type;
	char *p;

	payload_size = 0;
	io = &slave_thread->fsth_io;

	ncmsghdr = read_int(io, &ncmsghdr_len);
	payload_size += ncmsghdr_len;

	/* The master gives level and type at first to compute controllen */
	len = 0;
	specs = (struct cmsgspec *)alloca(sizeof(specs[0]) * ncmsghdr);
	for (i = 0; i < ncmsghdr; i++) {
		spec = &specs[i];

		level = read_int(io, &level_len);
		payload_size += level_len;
		type = read_int(io, &type_len);
		payload_size += type_len;
		spec->cmsgspec_level = level;
		spec->cmsgspec_type = type;

		switch (level) {
		case SOL_SOCKET:
			switch (type) {
			case SCM_CREDS:
				datasize = 0;
				break;
			case SCM_RIGHTS:
				nfds = read_int(io, &nfds_len);
				payload_size += nfds_len;
				spec->cmsgspec_nfds = nfds;
				datasize = sizeof(int) * nfds;
				break;
			default:
				return (ENOPROTOOPT);
			}
			break;
		default:
			return (ENOPROTOOPT);
		}

		cmsgspace = CMSG_SPACE(datasize);
		spec->cmsgspec_len = CMSG_LEN(datasize);
		spec->cmsgspec_space = cmsgspace;
		len += cmsgspace;
	}
	cmsghdrs = (struct cmsghdr *)mem_alloc(slave_thread, len);

	p = (char *)cmsghdrs;
	for (i = 0; i < ncmsghdr; i++) {
		cmsghdr = (struct cmsghdr *)p;

		spec = &specs[i];
		level = spec->cmsgspec_level;
		type = spec->cmsgspec_type;
		cmsghdr->cmsg_len = spec->cmsgspec_len;
		cmsghdr->cmsg_level = level;
		cmsghdr->cmsg_type = type;

		switch (level) {
		case SOL_SOCKET:
			switch (type) {
			case SCM_CREDS:
				/* nothing */
				break;
			case SCM_RIGHTS:
				pfd = (int *)CMSG_DATA(cmsghdr);
				nfds = spec->cmsgspec_nfds;
				for (j = 0; j < nfds; j++, pfd++) {
					*pfd = read_int(io, &fd_len);
					payload_size += fd_len;
				}
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}

		p += spec->cmsgspec_space;
	}

	*control = cmsghdrs;
	*controllen = len;
	*actual_payload_size = payload_size;

	return (0);
}

static void
process_sendmsg(struct slave_thread *slave_thread)
{
	struct msghdr msg;
	struct iovec *iov;
	struct io *io;
	sigset_t oset;
	payload_size_t actual_payload_size, cmsghdrs_len, controlcode_len;
	payload_size_t fd_len, flags_len, iovlen_len, len_len, msg_flags_len;
	payload_size_t namecode_len, payload_size, rest_size;
	size_t len;
	ssize_t retval;
	socklen_t controllen;
	command_t return_command;
	int controlcode, e, error, fd, flags, i, iovlen, namecode;
	const char *fmt, *sysname = "sendmsg";
	void *base, *control;

	return_command = SENDMSG_RETURN;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);

	fd = read_int(io, &fd_len);
	actual_payload_size = fd_len;

	namecode = read_int(io, &namecode_len);
	actual_payload_size += namecode_len;
	switch (namecode) {
	case MSGHDR_MSG_NAME_NOT_NULL:
		assert(actual_payload_size <= payload_size);
		rest_size = payload_size - actual_payload_size;
		drop_payload_to_error(slave_thread, return_command, rest_size,
				      EOPNOTSUPP);
		return;
	case MSGHDR_MSG_NAME_NULL:
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		break;
	default:
		assert(actual_payload_size <= payload_size);
		fmt = "%s: invalid namecode: %d";
		syslog(LOG_DEBUG, fmt, sysname, namecode);
		rest_size = payload_size - actual_payload_size;
		drop_payload_to_error(slave_thread, return_command, rest_size,
				      EINVAL);
		return;
	}

	iovlen = read_int(io, &iovlen_len);
	actual_payload_size += iovlen_len;
	msg.msg_iovlen = iovlen;
	msg.msg_iov = (struct iovec *)alloca(sizeof(struct iovec) * iovlen);

	for (i = 0; i < iovlen; i++) {
		iov = &msg.msg_iov[i];

		len = read_int(io, &len_len);
		actual_payload_size += len_len;
		iov->iov_len = len;

		base = (char *)alloca(len);
		read_or_die(io, base, len);
		actual_payload_size += len;
		iov->iov_base = base;
	}

	controlcode = read_int(io, &controlcode_len);
	actual_payload_size += controlcode_len;
	switch (controlcode) {
	case MSGHDR_MSG_CONTROL_NOT_NULL:
		error = read_cmsghdrs(slave_thread, (struct cmsghdr **)&control,
				      &controllen, &cmsghdrs_len);
		if (error != 0) {
			syslog(LOG_DEBUG, "%s: cannot read cmsghdr", sysname);
			rest_size = payload_size - actual_payload_size;
			drop_payload_to_error(slave_thread, return_command,
					      rest_size, error);
			return;
		}
		actual_payload_size += cmsghdrs_len;
		break;
	case MSGHDR_MSG_CONTROL_NULL:
		control = NULL;
		controllen = 0;
		break;
	default:
		fmt = "%s: invalid controlcode: %d";
		syslog(LOG_DEBUG, fmt, sysname, controlcode);
		rest_size = payload_size - actual_payload_size;
		drop_payload_to_error(slave_thread, return_command, rest_size,
				      EINVAL);
		return;
	}
	msg.msg_control = control;
	msg.msg_controllen = controllen;

	msg.msg_flags = read_int(io, &msg_flags_len);
	actual_payload_size += msg_flags_len;

	flags = read_int(io, &flags_len);
	actual_payload_size += flags_len;

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	suspend_signal(slave_thread, &oset);
	retval = sendmsg(fd, &msg, flags);
	e = errno;
	resume_signal(slave_thread, &oset);

	return_ssize(slave_thread, return_command, retval, e);
}

static void
process_sigprocmask(struct slave_thread *slave_thread)
{
	struct slave *slave;
	struct io *io;
	sigset_t *pset, set;
	payload_size_t actual_payload_size, how_len, payload_size, set_len;
	int errnum, how, retval;

	pset = &set;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);

	how = read_int(io, &how_len);
	actual_payload_size = how_len;
	read_sigset(io, pset, &set_len);
	actual_payload_size += set_len;

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	slave = slave_thread->fsth_slave;
	writelock_slave(slave);
	switch (how) {
	case SIG_BLOCK:
		merge_sigset(slave, pset, sigaddset, &retval, &errnum);
		break;
	case SIG_UNBLOCK:
		merge_sigset(slave, pset, sigdelset, &retval, &errnum);
		break;
	case SIG_SETMASK:
		memcpy(&slave->mask, pset, sizeof(slave->mask));
		retval = errnum = 0;
		break;
	default:
		retval = -1;
		errnum = EINVAL;
		break;
	}
	unlock_slave(slave);

	return_int(slave_thread, SIGPROCMASK_RETURN, retval, errnum);
}

static void
signal_handler(int sig)
{
	char c = (char)sig;

	write_or_die(&sigw, &c, sizeof(c));
}

static void
initialize_signal_handling(struct slave *slave)
{
	int fds[2];
	const char *fmt = "initialized signal handling: sigr=%s, sigw=%s";
	char s1[256], s2[256];

	if (pipe(fds) == -1)
		die(1, "cannot pipe(2) in initializing signal handling");
	io_init_nossl(&slave->fsla_sigr, fds[0], -1, vsyslog);
	io_init_nossl(&sigw, -1, fds[1], vsyslog);
	io_dump(&slave->fsla_sigr, s1, sizeof(s1));
	io_dump(&sigw, s2, sizeof(s2));
	syslog(LOG_DEBUG, fmt, s1, s2);
}

static int
connect_to_shub(struct slave *slave, const char *token, size_t token_size)
{
	struct sockaddr_storage sockaddr;
	struct sockaddr_un *addr;
	struct io io;
	int sock;
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
	syslog(LOG_DEBUG, "connected to fshub: socket=%d", sock);

	io_init_nossl(&io, sock, sock, vsyslog);
	write_or_die(&io, token, token_size);

	return (sock);
}

static void
child_main(struct slave_thread *slave_thread, const char *token,
	   size_t token_size, pid_t parent, sigset_t *sigset)
{
	struct slave_thread *thread, *tmp;
	struct slave *slave;
	int sock;
	char s[256];

	slave = slave_thread->fsth_slave;
	SLIST_FOREACH_SAFE(thread, &slave->fsla_slaves, fsth_next, tmp)
		if (thread != slave_thread)
			release_slave_thread(thread);

	close_slave_thread(slave_thread);
	sock = connect_to_shub(slave, token, token_size);
	io_init_nossl(&slave_thread->fsth_io, sock, sock, vsyslog);
	slave_thread->fsth_signal_watcher = true;

	if (io_close(&slave->fsla_sigr) != 0)
		diec(1, slave->fsla_sigr.io_error, "Cannot close(2) for sigr");
	if (io_close(&sigw) != 0)
		diec(1, sigw.io_error, "Cannot close(2) for sigw");
	initialize_signal_handling(slave);
	if (sigprocmask(SIG_SETMASK, sigset, NULL) == -1)
		die(1, "sigprocmask(2) to recover failed");
	io_dump(&slave_thread->fsth_io, s, sizeof(s));
	syslog(LOG_INFO, "A new child process has started: io=%s", s);
}

static void
read_token(struct slave_thread *slave_thread, char **token,
	   payload_size_t *token_size)
{
	struct io *io;
	payload_size_t payload_size;
	char *s;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);
	s = (char *)mem_alloc(slave_thread, payload_size);
	read_or_die(io, s, payload_size);

	*token = s;
	*token_size = payload_size;
}

static void *
thread_main(void *arg)
{
	struct slave_thread *slave_thread;

	syslog(LOG_DEBUG, "new thread started");
	slave_thread = (struct slave_thread *)arg;
	mainloop(slave_thread);
	release_slave_thread(slave_thread);

	return (NULL);
}

static void
add_thread(struct slave *slave, struct slave_thread *slave_thread)
{

	writelock_slave(slave);
	SLIST_INSERT_HEAD(&slave->fsla_slaves, slave_thread, fsth_next);
	unlock_slave(slave);
}

static struct slave_thread *
malloc_slave_thread()
{
	size_t size;

	size = sizeof(struct slave_thread);

	return (struct slave_thread *)malloc_or_die(size);
}

static void
start_new_thread(struct slave *slave, const char *token, size_t token_size)
{
	struct slave_thread *new_thread;
	pthread_t thread;
	int error, sock;

	sock = connect_to_shub(slave, token, token_size);

	new_thread = malloc_slave_thread();
	new_thread->fsth_slave = slave;
	SLIST_INIT(&new_thread->fsth_memory);
	io_init_nossl(&new_thread->fsth_io, sock, sock, vsyslog);
	new_thread->fsth_signal_watcher = false;
	add_thread(slave, new_thread);

	error = pthread_create(&thread, NULL, thread_main, new_thread);
	if (error != 0)
		diec(1, error, "pthread_create(3) failed");
}

static void
process_thr_new(struct slave_thread *slave_thread)
{
	payload_size_t token_size;
	char *token;

	read_token(slave_thread, &token, &token_size);
	start_new_thread(slave_thread->fsth_slave, token, token_size);
	return_int(slave_thread, THR_NEW_RETURN, 0, 0);
}

static void
process_fork(struct slave_thread *slave_thread)
{
	struct io *io;
	sigset_t oset, set;
	payload_size_t len, token_size;
	pid_t parent_pid, pid;
	char buf[FSYSCALL_BUFSIZE_INT32], *token;

	read_token(slave_thread, &token, &token_size);

	if (sigfillset(&set) == -1)
		die(1, "sigfillset(3) failed");
	if (sigprocmask(SIG_BLOCK, &set, &oset) == -1)
		die(1, "sigprocmask(2) to block all signals failed");

	parent_pid = getpid();
	pid = fork_or_die();
	if (pid == 0) {
		child_main(slave_thread, token, token_size, parent_pid, &oset);
		return;
	}
	syslog(LOG_DEBUG, "forked: pid=%d", pid);
	if (sigprocmask(SIG_SETMASK, &oset, NULL) == -1)
		die(1, "sigprocmask(2) to recover failed");

	len = encode_int32(pid, buf, sizeof(buf));
	io = &slave_thread->fsth_io;
	write_command(io, FORK_RETURN);
	write_payload_size(io, len);
	write_or_die(io, buf, len);
}

static void
process_kevent(struct slave_thread *slave_thread)
{
	struct io *io;
	struct kevent *changelist, *eventlist, *kev;
	struct payload *payload;
	struct timespec timeout, *ptimeout;
	sigset_t oset;
	payload_size_t actual_payload_size, len, payload_size;
	size_t size;
	command_t return_command;
	int changelist_code, e, i, kq, nchanges, nevents, retval;
	int timeout_code, udata_code;
	const char *fmt = "Invalid kevent(2) changelist code: %d";
	const char *fmt2 = "Invalid kevent(2) timeout code: %d";

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);

	kq = read_int(io, &len);
	actual_payload_size = len;

	nchanges = read_int(io, &len);
	actual_payload_size += len;

	changelist_code = read_int(io, &len);
	actual_payload_size += len;

	switch (changelist_code) {
	case KEVENT_CHANGELIST_NOT_NULL:
		size = sizeof(*changelist) * nchanges;
		changelist = (struct kevent *)alloca(size);
		for (i = 0; i < nchanges; i++) {
			kev = &changelist[i];
			kev->ident = read_ulong(io, &len);
			actual_payload_size += len;
			kev->filter = read_short(io, &len);
			actual_payload_size += len;
			kev->flags = read_ushort(io, &len);
			actual_payload_size += len;
			kev->fflags = read_uint(io, &len);
			actual_payload_size += len;
			kev->data = read_long(io, &len);
			actual_payload_size += len;
			udata_code = read_int(io, &len);
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
		changelist = NULL;	/* for -Wsometimes-uninitialized */
		die(1, fmt, changelist_code);
		break;
	}

	nevents = read_int(io, &len);
	actual_payload_size += len;
	eventlist = (struct kevent *)alloca(sizeof(*eventlist) * nevents);

	timeout_code = read_int(io, &len);
	actual_payload_size += len;

	switch (timeout_code) {
	case KEVENT_TIMEOUT_NOT_NULL:
		timeout.tv_sec = read_int64(io, &len);
		actual_payload_size += len;
		timeout.tv_nsec = read_int64(io, &len);
		actual_payload_size += len;
		ptimeout = &timeout;
		break;
	case KEVENT_TIMEOUT_NULL:
		ptimeout = NULL;
		break;
	default:
		ptimeout = NULL;	/* for -Wsometimes-uninitialized */
		die(1, fmt2, timeout_code);
		break;
	}

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	suspend_signal(slave_thread, &oset);
	retval = kevent(kq, changelist, nchanges, eventlist, nevents, ptimeout);
	e = errno;
	resume_signal(slave_thread, &oset);
	syslog(LOG_DEBUG,
	       "kevent: kq=%d, nchanges=%d, nevents=%d, retval=%d",
	       kq, nchanges, nevents, retval);
	return_command = KEVENT_RETURN;
	if (retval == -1) {
		return_int(slave_thread, return_command, retval, e);
		return;
	}

	payload = payload_create();
	payload_add_int(payload, retval);
	for (i = 0; i < retval; i++)
		payload_add_kevent(payload, &eventlist[i]);
	write_payloaded_command(slave_thread, return_command, payload);
	payload_dispose(payload);
}

static void
process_setsockopt(struct slave_thread *slave_thread)
{
	struct io *io;
	sigset_t oset;
	payload_size_t actual_payload_size, level_len, optname_len, optlen_len;
	payload_size_t optval_len, payload_size, s_len;
	socklen_t optlen;
	int e, level, n, optname, retval, s;
	void *optval;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);

	s = read_int32(io, &s_len);
	actual_payload_size = s_len;

	level = read_int32(io, &level_len);
	actual_payload_size += level_len;

	optname = read_int32(io, &optname_len);
	actual_payload_size += optname_len;

	optlen = read_socklen(io, &optlen_len);
	actual_payload_size += optlen_len;

	switch (optname) {
	case SO_REUSEADDR:
		n = read_int(io, &optval_len);
		actual_payload_size += optval_len;
		break;
	default:
		die(1, "Unsupported socket option specified: %s", optname);
		break;
	}
	optval = &n;

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	suspend_signal(slave_thread, &oset);
	retval = setsockopt(s, level, optname, optval, optlen);
	e = errno;
	resume_signal(slave_thread, &oset);

	return_int(slave_thread, SETSOCKOPT_RETURN, retval, e);
}

static void
process_getsockopt(struct slave_thread *slave_thread)
{
	struct io *io;
	struct payload *payload;
	sigset_t oset;
	payload_size_t actual_payload_size, level_len, optname_len, optlen_len;
	payload_size_t payload_size, s_len;
	socklen_t optlen;
	int e, level, optname, retval, s;
	void *optval;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);

	s = read_int32(io, &s_len);
	actual_payload_size = s_len;

	level = read_int32(io, &level_len);
	actual_payload_size += level_len;

	optname = read_int32(io, &optname_len);
	actual_payload_size += optname_len;

	optlen = read_socklen(io, &optlen_len);
	actual_payload_size += optlen_len;

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	optval = alloca(optlen);
	suspend_signal(slave_thread, &oset);
	retval = getsockopt(s, level, optname, optval, &optlen);
	e = errno;
	resume_signal(slave_thread, &oset);

	if (retval == -1) {
		return_int(slave_thread, GETSOCKOPT_RETURN, retval, e);
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
		return_int(slave_thread, GETSOCKOPT_RETURN, -1, ENOPROTOOPT);
		goto exit;
	}

	write_payloaded_command(slave_thread, GETSOCKOPT_RETURN, payload);

exit:
	payload_dispose(payload);
}

static void
process_select(struct slave_thread *slave_thread)
{
	sigset_t oset;
	struct timeval *ptimeout, timeout;
	fd_set exceptfds, readfds, writefds;
	int e, nfds, retval;

	FD_ZERO(&exceptfds);
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	read_select_parameters(slave_thread, &nfds, &readfds, &writefds,
			       &exceptfds, &timeout, &ptimeout);

	suspend_signal(slave_thread, &oset);
	retval = select(nfds, &readfds, &writefds, &exceptfds, ptimeout);
	e = errno;
	resume_signal(slave_thread, &oset);

	switch (retval) {
	case -1:
		return_int(slave_thread, SELECT_RETURN, retval, e);
		break;
	case 0:
		write_select_timeout(slave_thread);
		break;
	default:
		write_select_ready(slave_thread, retval, nfds, &readfds,
				   &writefds, &exceptfds);
		break;
	}
}

static void
process_thr_exit(struct slave_thread *slave_thread)
{

	pthread_exit(NULL);
	/* NOTREACHED */
	die(2, "pthread_exit(3) returned???");
}

static int
process_exit(struct slave_thread *slave_thread)
{
	payload_size_t _;
	int status;

	status = read_int32(&slave_thread->fsth_io, &_);

	syslog(LOG_DEBUG, "EXIT_CALL: status=%d", status);

	return (status);
}

static void
process_utimes(struct slave_thread *slave_thread)
{
	struct io *io;
	sigset_t oset;
	struct timeval *ptimes, times[2];
	payload_size_t actual_payload_size, path_len, payload_size;
	payload_size_t times_code_len, times_len;
	int e, i, ntimes, retval;
	const char *path;
	uint8_t times_code;

	io = &slave_thread->fsth_io;
	actual_payload_size = 0;
	payload_size = read_payload_size(io);

	path = read_string(io, &path_len);
	actual_payload_size += path_len;

	times_code = read_uint8(io, &times_code_len);
	actual_payload_size += times_code_len;

	switch (times_code) {
	case UTIMES_TIMES_NULL:
		ptimes = NULL;
		break;
	case UTIMES_TIMES_NOT_NULL:
		ntimes = array_sizeof(times);
		for (i = 0; i < ntimes; i++) {
			read_timeval(io, &times[i], &times_len);
			actual_payload_size += times_len;
		}
		ptimes = times;
		break;
	default:
		ptimes = NULL;	/* for -Wsometimes-uninitialized */
		die(1, "invalid utimes(2) times code: %d", times_code);
		break;
	}

	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	suspend_signal(slave_thread, &oset);
	retval = utimes(path, ptimes);
	e = errno;
	resume_signal(slave_thread, &oset);

	return_int(slave_thread, UTIMES_RETURN, retval, e);
}

struct getdirentries_args {
	int fd;
	int nentmax;
};

static void
read_getdirentries_args(struct slave_thread *slave_thread,
			struct getdirentries_args *args)
{
	struct io *io;
	payload_size_t actual_payload_size, fd_len, nentmax_len, payload_size;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);

	args->fd = read_int(io, &fd_len);
	actual_payload_size = fd_len;

	args->nentmax = read_int(io, &nentmax_len);
	actual_payload_size += nentmax_len;

	die_if_payload_size_mismatched(payload_size, actual_payload_size);
}

static int
count_dirent(const char *buf, int bufsize, int nentmax)
{
	const struct dirent *dirent;
	int nent;
	const char *bufend, *p;

	bufend = buf + bufsize;
	for (p = buf, nent = 0;
	     (p < bufend) && (nent < nentmax);
	     p += dirent->d_reclen, nent++)
		dirent = (const struct dirent *)p;

	return (nent);
}

static void
write_getdirentries_result(struct slave_thread *slave_thread, int retval, int e,
			   int nentmax, const char *buf, long base)
{
	struct payload *payload;
	const struct dirent *dirent;
	command_t return_command;
	int i, nent;
	const char *p;

	return_command = GETDIRENTRIES_RETURN;
	if (retval == -1) {
		return_int(slave_thread, return_command, retval, e);
		return;
	}

	nent = count_dirent(buf, retval, nentmax);

	payload = payload_create();
	payload_add_int(payload, retval);
	payload_add_int(payload, nent);
	for (i = 0, p = buf; i < nent; i++, p += dirent->d_reclen) {
		dirent = (const struct dirent *)p;
		payload_add_dirent(payload, dirent);
	}
	payload_add_long(payload, base);

	write_payloaded_command(slave_thread, return_command, payload);

	payload_dispose(payload);
}

static int
do_getdirentries(struct slave_thread *slave_thread, int fd, char *buf,
		 int nbytes, int nentmax)
{
	struct dir_entries_cache *cache;
	sigset_t oset;
	long base;
	int e, retval, status;

	cache = slave_thread->fsth_slave->fsla_dir_entries_cache;
	dir_entries_cache_lock(cache, fd);

	status = dir_entries_cache_get(cache, fd, buf, nbytes, nentmax);
	if (0 < status)
		goto exit;

	suspend_signal(slave_thread, &oset);
	retval = getdirentries(fd, buf, nbytes, &base);
	e = errno;
	resume_signal(slave_thread, &oset);
	dir_entries_cache_put(cache, fd, buf, nbytes, nentmax);

	status = retval != -1 ? retval : - e;
exit:
	dir_entries_cache_unlock(cache, fd);

	return (status);
}

static void
process_getdirentries(struct slave_thread *slave_thread)
{
	struct getdirentries_args args;
	int e, nbytes, nentmax, retval, status;
	char *buf;

	read_getdirentries_args(slave_thread, &args);

	nentmax = args.nentmax;
	nbytes = sizeof(struct dirent) * nentmax;
	buf = mem_alloc(slave_thread, nbytes);

	status = do_getdirentries(slave_thread, args.fd, buf, nbytes, nentmax);
	if (0 <= status) {
		retval = status;
		e = 0;	/* clang rejects when this statement does not exist */
	}
	else {
		retval = -1;
		e = - status;
	}

	write_getdirentries_result(slave_thread, retval, e, nentmax, buf, 0L);
}

static void
process_openat(struct slave_thread *slave_thread)
{
	struct io *io;
	sigset_t oset;
	payload_size_t actual_payload_size, fd_len, flags_len, mode_len;
	payload_size_t path_len, payload_size;
	int e, fd, flags, retval;
	mode_t mode;
	char *path;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);

	fd = read_int(io, &fd_len);
	actual_payload_size = fd_len;

	path = read_string(io, &path_len);
	actual_payload_size += path_len;

	flags = read_int(io, &flags_len);
	actual_payload_size += flags_len;

	if ((flags & O_CREAT) != 0) {
		mode = read_mode(io, &mode_len);
		actual_payload_size += mode_len;
	}
	else
		mode = 0;

	suspend_signal(slave_thread, &oset);
	retval = openat(fd, path, flags, mode);
	e = errno;
	resume_signal(slave_thread, &oset);

	return_int(slave_thread, OPENAT_RETURN, retval, e);
	free(path);
}

static void
process_fcntl(struct slave_thread *slave_thread)
{
	struct io *io;
	sigset_t oset;
	payload_size_t actual_payload_size, arg_len, cmd_len, fd_len;
	payload_size_t payload_size;
	long arg;
	int cmd, e, fd, retval;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);

	fd = read_int(io, &fd_len);
	actual_payload_size = fd_len;

	cmd = read_int(io, &cmd_len);
	actual_payload_size += cmd_len;

	switch (cmd) {
	case F_GETFD:
	case F_GETFL:
		arg = 42L;	/* for -Wsometimes-uninitialized. unused */
		break;
	case F_SETFD:
	case F_SETFL:
	default:
		arg = read_long(io, &arg_len);
		actual_payload_size += arg_len;
		break;
	}

	suspend_signal(slave_thread, &oset);
	retval = fcntl(fd, cmd, arg);
	e = errno;
	resume_signal(slave_thread, &oset);

	return_int(slave_thread, FCNTL_RETURN, retval, e);
}

static const char *
zlib_errno(int e)
{

#define	CASE(n)	case n: return #n

	switch (e) {
	CASE(Z_OK);
	CASE(Z_STREAM_END);
	CASE(Z_NEED_DICT);
	CASE(Z_ERRNO);
	CASE(Z_STREAM_ERROR);
	CASE(Z_DATA_ERROR);
	CASE(Z_MEM_ERROR);
	CASE(Z_BUF_ERROR);
	CASE(Z_VERSION_ERROR);
	default:
		return "unknown error";
	}

#undef	CASE
}

static void
decompress(struct slave_thread *slave_thread, char **out,
	   payload_size_t *outsize, char *in, size_t insize)
{
	z_stream z;
	size_t bufsize, size, tmpsize;
	int zerror;
	Bytef *tmp;
	char *buf, *p;

	bzero(&z, sizeof(z));
	z.next_in = Z_NULL;
	z.avail_in = 0;
	z.zalloc = Z_NULL;
	z.zfree = Z_NULL;
	z.opaque = Z_NULL;
	z.data_type = Z_BINARY;
	zerror = inflateInit(&z);
	if (zerror != Z_OK)
		diex(1, "inflateInit() failed with %d (%s)",
			zerror, zlib_errno(zerror));

	buf = NULL;
	bufsize = 0;
	z.next_in = (Bytef *)in;
	z.avail_in = insize;
	tmpsize = 8192;
	tmp = (Bytef *)mem_alloc(slave_thread, tmpsize);
	while (0 < z.avail_in) {
		z.next_out = tmp;
		z.avail_out = tmpsize;
		zerror = inflate(&z, Z_NO_FLUSH);
#if 0
		syslog(LOG_DEBUG,
		       "inflate: zerror=%d (%s), buf=%p, bufsize=%zu, tmp=%p, t"
		       "mpsize=%zu, in=%p, insize=%zu, z.next_in=%p, z.avail_in"
		       "=%d, z.total_in=%lu, z.next_out=%p, z.avail_out=%d, z.t"
		       "otal_out=%lu, z.msg=%s",
		       zerror, zlib_errno(zerror), buf, bufsize, tmp, tmpsize,
		       in, insize, z.next_in, z.avail_in, z.total_in,
		       z.next_out, z.avail_out, z.total_out,
		       z.msg != NULL ? z.msg : "NULL");
#endif
		switch (zerror) {
		case Z_OK:
		case Z_STREAM_END:
			size = tmpsize - z.avail_out;
			p = (char *)mem_alloc(slave_thread, bufsize + size);
			memcpy(&p[0], buf, bufsize);
			memcpy(&p[bufsize], tmp, size);
			buf = p;
			bufsize += size;
			break;
		case Z_BUF_ERROR:
			tmpsize += 8192;
			tmp = (Bytef *)mem_alloc(slave_thread, tmpsize);
			break;
		default:
			diex(1, "inflate() failed with %d (%s)",
				zerror, zlib_errno(zerror));
			break;
		}
	}

	zerror = inflateEnd(&z);
	if (zerror != Z_OK)
		diex(1, "inflateEnd() failed with %d (%s)",
			zerror, zlib_errno(zerror));

#if 0
	/*
	 * If you use this code, include <md5.h> and add a "-lmd" option to the
	 * LDADD in the Makefile.
	 */
	char md5[256];
	MD5_CTX ctx;
	MD5Init(&ctx);
	MD5Update(&ctx, buf, bufsize);
	MD5End(&ctx, md5);
	syslog(LOG_DEBUG, "decompressed payload md5: %s", md5);
#endif

	*out = buf;
	*outsize = bufsize;
}

static void
process_compressed_writev(struct slave_thread *slave_thread)
{
	sigset_t oset;
	struct io *io;
	struct stream st;
	struct iovec *iovec, *iovp;
	payload_size_t bufsize, payload_size;
	size_t len;
	int errnum, fd, i, iovcnt, retval;
	char *buf, *payload;
	void *base;

	io = &slave_thread->fsth_io;
	payload_size = read_payload_size(io);
	payload = (char *)alloca(payload_size);
	read_or_die(io, payload, payload_size);
	decompress(slave_thread, &buf, &bufsize, payload, payload_size);

	stream_init(&st, buf, bufsize);
	fd = stream_get_int(&st);
	iovcnt = stream_get_int(&st);
	iovp = (struct iovec *)alloca(sizeof(iovp[0]) * iovcnt);
	for (i = 0; i < iovcnt; i++) {
		len = stream_get_size(&st);
		base = alloca(len);
		stream_get(&st, base, len);
		iovec = &iovp[i];
		iovec->iov_len = len;
		iovec->iov_base = base;
	}

	suspend_signal(slave_thread, &oset);
	retval = writev(fd, iovp, iovcnt);
	errnum = errno;
	resume_signal(slave_thread, &oset);
	return_int(slave_thread, WRITEV_RETURN, retval, errnum);
}

static int
mainloop(struct slave_thread *slave_thread)
{
	struct io *ios[2];
	command_t cmd;
	int error, nios;
	const char *name;

	for (;;) {
		ios[0] = &slave_thread->fsth_io;

		if (slave_thread->fsth_signal_watcher) {
			ios[1] = &slave_thread->fsth_slave->fsla_sigr;
			nios = 2;
		}
		else
			nios = 1;

		if (io_select(nios, ios, NULL, &error) == -1) {
			if (error != EINTR)
				diec(1, error, "select(2) failed");
			continue;
		}

		if (slave_thread->fsth_signal_watcher && io_is_readable(ios[1]))
			process_signal(slave_thread);

		if (io_is_readable(ios[0])) {
			cmd = read_command(ios[0]);
			name = get_command_name(cmd);
			syslog(LOG_DEBUG, "processing %s.", name);
			switch (cmd) {
#include "dispatch.inc"
			case CLOSE_CALL:
				process_close(slave_thread);
				break;
			case FORK_CALL:
				process_fork(slave_thread);
				break;
			case SELECT_CALL:
				process_select(slave_thread);
				break;
			case CONNECT_CALL:
				process_connect_protocol(slave_thread,
							 CONNECT_CALL,
							 CONNECT_RETURN,
							 connect);
				break;
			case BIND_CALL:
				process_connect_protocol(slave_thread,
							 BIND_CALL, BIND_RETURN,
							 bind);
				break;
			case GETPEERNAME_CALL:
				process_accept_protocol(slave_thread,
							GETPEERNAME_CALL,
							GETPEERNAME_RETURN,
							getpeername);
				break;
			case GETSOCKNAME_CALL:
				process_accept_protocol(slave_thread,
							GETSOCKNAME_CALL,
							GETSOCKNAME_RETURN,
							getsockname);
				break;
			case ACCEPT_CALL:
				process_accept_protocol(slave_thread,
							ACCEPT_CALL,
							ACCEPT_RETURN, accept);
				break;
			case POLL_CALL:
				process_poll(slave_thread);
				break;
			case GETSOCKOPT_CALL:
				process_getsockopt(slave_thread);
				break;
			case SETSOCKOPT_CALL:
				process_setsockopt(slave_thread);
				break;
			case KEVENT_CALL:
				process_kevent(slave_thread);
				break;
			case POLL_START:
				process_poll_start(slave_thread);
				break;
			case SIGPROCMASK_CALL:
				process_sigprocmask(slave_thread);
				break;
			case SENDMSG_CALL:
				process_sendmsg(slave_thread);
				break;
			case RECVMSG_CALL:
				process_recvmsg(slave_thread);
				break;
			case THR_NEW_CALL:
				process_thr_new(slave_thread);
				break;
			case UTIMES_CALL:
				process_utimes(slave_thread);
				break;
			case GETDIRENTRIES_CALL:
				process_getdirentries(slave_thread);
				break;
			case FCNTL_CALL:
				process_fcntl(slave_thread);
				break;
			case OPENAT_CALL:
				process_openat(slave_thread);
				break;
			case ACCEPT4_CALL:
				process_accept4(slave_thread);
				break;
			case COMPRESSED_WRITEV_CALL:
				process_compressed_writev(slave_thread);
				break;
			case EXIT_CALL:
				return process_exit(slave_thread);
			case THR_EXIT_CALL:
				process_thr_exit(slave_thread);
				break;
			default:
				diex(-1, "unknown command (%d)", cmd);
				/* NOTREACHED */
			}
		}

		mem_freeall(slave_thread);
	}

	return (-1);
}

static int
slave_main(struct slave_thread *slave_thread)
{
	negotiate_version(slave_thread);
	//write_pid(slave->wfd, getpid());
	write_open_fds(slave_thread);

	return (mainloop(slave_thread));
}

static int
initialize_sigaction()
{
	struct sigaction act;
	int i, sig;
	const char *fmt = "cannot sigaction(2) for %d (SIG%s)";

	act.sa_handler = signal_handler;
	act.sa_flags = SA_RESTART;
	if (sigfillset(&act.sa_mask) == -1)
		die(1, "cannot sigemptyset(3)");

	for (i = 0; i < nsigs; i++) {
		sig = sigs[i];
		if (sigaction(sig, &act, NULL) == -1)
			die(1, fmt, sig, sys_signame[sig]);
	}

	return (0);
}

static void
initialize_slave(struct slave *slave, const char *fork_sock)
{
	int error;
	char *s;

	error = pthread_rwlock_init(&slave->fsla_lock, NULL);
	if (error != 0)
		diex(error, "pthread_rwlock_init(3) failed");

	SLIST_INIT(&slave->fsla_slaves);
	slave->fsla_dir_entries_cache = dir_entries_cache_create();
	initialize_signal_handling(slave);

	s = strdup(fork_sock);
	if (s == NULL)
		die(1, "cannot strdup(3) the fork socket: %s", fork_sock);
	slave->fork_sock = s;

	if (sigprocmask(SIG_BLOCK, NULL, &slave->mask) == -1)
		die(1, "cannot sigprocmask(2) in initializing the slave");
}

int
main(int argc, char* argv[])
{
	struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	struct slave *slave;
	struct slave_thread *slave_thread;
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

	slave = (struct slave *)malloc_or_die(sizeof(*slave));
	initialize_slave(slave, args[2]);

	slave_thread = malloc_slave_thread();
	slave_thread->fsth_slave = slave;
	SLIST_INIT(&slave_thread->fsth_memory);
	io_init_nossl(&slave_thread->fsth_io, atoi_or_die(args[0], "rfd"),
		      atoi_or_die(args[1], "wfd"), vsyslog);
	slave_thread->fsth_signal_watcher = true;
	add_thread(slave, slave_thread);

	if (initialize_sigaction() != 0)
		return (4);

	status = slave_main(slave_thread);
	release_slave_thread(slave_thread);
	log_graceful_exit(status);

	return (status);
}

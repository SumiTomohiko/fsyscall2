#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/select.h>
#include <sys/selinfo.h>
#include <sys/socket.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/payload.h>
#include <fsyscall/private/read_sockaddr.h>

MALLOC_DEFINE(M_FMASTER, "fmaster", "fmaster");

struct fmaster_data *
fmaster_create_data(struct thread *td)
{
	struct fmaster_data *data;
	int flags = M_NOWAIT;

	data = (struct fmaster_data *)malloc(sizeof(*data), M_FMASTER, flags);

	return (data);
}

void
fmaster_delete_data(struct fmaster_data *data)
{

	free(data, M_FMASTER);
}

long
fmaster_subtract_timeval(const struct timeval *t1, const struct timeval *t2)
{
	time_t diff;

	diff = t2->tv_sec - t1->tv_sec;

	return (1000000 * diff + (t2->tv_usec - t1->tv_usec));
}

void
fmaster_log_syscall_end(struct thread *td, const char *name,
			const struct timeval *t1, int error)
{
	struct timeval t2;
	long delta;
	const char *fmt = "fmaster[%d]: %s: ended: error=%d: %ld[usec]\n";

	microtime(&t2);
	delta = fmaster_subtract_timeval(t1, &t2);
	log(LOG_DEBUG, fmt, td->td_proc->p_pid, name, error, delta);
}

int
fmaster_is_master_file(struct thread *td, const char *path)
{
	int i;
	const char *dirs[] = {
		"/lib/",
		"/usr/lib/",
		"/usr/local/etc/fonts/conf.d/",
		"/usr/local/etc/pango/",
		"/usr/local/lib/",
		"/usr/local/share/fonts/",
		"/var/db/fontconfig/",
	};
	const char *files[] = {
		"/usr/local/etc/dbus-1/session.conf",
		"/usr/local/etc/dbus-1/session.d",
		"/dev/null",
		"/dev/urandom",
		"/etc/nsswitch.conf",
		"/etc/pwd.db",
		"/usr/local/etc/fonts/fonts.conf",
		"/usr/local/share/applications/gedit.desktop",
		"/var/db/dbus/machine-id",
		"/var/run/ld-elf.so.hints"
	};
	const char *s;

	for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		s = dirs[i];
		if (strncmp(path, s, strlen(s)) == 0)
			return (1);
	}
	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		if (strcmp(path, files[i]) == 0)
			return (1);
	}

	return (0);
}

static void
die(struct thread *td, const char *cause)
{
	pid_t pid = td->td_proc->p_pid;

	log(LOG_INFO, "fmaster[%d]: die: %s\n", pid, cause);
	exit1(td, 1);
}

static int
kevent_copyout(void *arg, struct kevent *kevp, int count)
{
	struct kevent *kev;

	if (1 < count)
		return (EINVAL);

	kev = (struct kevent *)arg;
	memcpy(kev, kevp, sizeof(*kev) * count);

	return (0);
}

static int
wait_data(struct thread *td)
{
	struct kevent kev;
	struct timespec timeout;
	struct kevent_copyops k_ops;
	int error, kq;

	kq = fmaster_data_of_thread(td)->kq;
	timeout.tv_sec = 8;
	timeout.tv_nsec = 0;
	k_ops.arg = &kev;
	k_ops.k_copyin = NULL;
	k_ops.k_copyout = kevent_copyout;
	error = kern_kevent(td, kq, 0, 1, &k_ops, &timeout);
	if (error != 0)
		return (error);
	if (td->td_retval[0] == 0)
		return (ETIMEDOUT);
	fmaster_data_of_thread(td)->rfdlen += kev.data;

	return (0);
}

static int
do_readv(struct thread *td, int d, void *buf, size_t nbytes, int segflg)
{
	struct uio auio;
	struct iovec aiov;
	int error;

	if (INT_MAX < nbytes)
		return (EINVAL);

	aiov.iov_base = buf;
	aiov.iov_len = nbytes;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbytes;
	auio.uio_segflg = segflg;

	error = 0;
	while (0 < auio.uio_resid) {
		if (fmaster_data_of_thread(td)->rfdlen == 0) {
			error = wait_data(td);
			if (error != 0)
				return (error);
		}
		error = kern_readv(td, d, &auio);
		if (error != 0)
			return (error);
		if (td->td_retval[0] == 0)
			die(td, "readv");
		fmaster_data_of_thread(td)->rfdlen -= td->td_retval[0];
	}

	return (error);
}

int
fmaster_read(struct thread *td, int d, void *buf, size_t nbytes)
{

	return do_readv(td, d, buf, nbytes, UIO_SYSSPACE);
}

static int
rs_read_socklen(struct rsopts *opts, socklen_t *socklen, int *len)
{
	struct thread *td = (struct thread *)opts->rs_bonus;
	int error;

	error = fmaster_read_socklen(td, socklen, len);

	return (error);
}

static int
rs_read_uint64(struct rsopts *opts, uint64_t *n, int *len)
{
	struct thread *td = (struct thread *)opts->rs_bonus;
	int error;

	error = fmaster_read_uint64(td, n, len);

	return (error);
}

static int
rs_read_uint8(struct rsopts *opts, uint8_t *n, int *len)
{
	struct thread *td = (struct thread *)opts->rs_bonus;
	int error;

	error = fmaster_read_uint8(td, n, len);

	return (error);
}

static int
rs_read(struct rsopts *opts, char *buf, int len)
{
	struct thread *td = (struct thread *)opts->rs_bonus;
	int error, rfd;

	rfd = fmaster_rfd_of_thread(td);
	error = fmaster_read(td, rfd, buf, len);

	return (error);
}

static void *
rs_malloc(struct rsopts *opts, size_t size)
{

	return malloc(size, M_TEMP, M_WAITOK | M_ZERO);
}

static void
rs_free(struct rsopts *opts, void *ptr)
{

	free(ptr, M_TEMP);
}

int
fmaster_read_sockaddr(struct thread *td, struct sockaddr_storage *addr,
		      int *len)
{
	struct rsopts opts;
	int error;

	opts.rs_bonus = td;
	opts.rs_read_socklen = rs_read_socklen;
	opts.rs_read_uint8 = rs_read_uint8;
	opts.rs_read_uint64 = rs_read_uint64;
	opts.rs_read = rs_read;
	opts.rs_malloc = rs_malloc;
	opts.rs_free = rs_free;

	error = fsyscall_read_sockaddr(&opts, addr, len);

	return (error);
}

static int
read_numeric_sequence(struct thread *td, int fd, char *buf, int bufsize, int *size)
{
	int error;
	char *p, *pend;

	pend = buf + bufsize;
	p = buf;
	error = fmaster_read(td, fd, p, sizeof(*p));
	while ((error == 0) && ((*p & 0x80) != 0) && (p + 1 < pend)) {
		p++;
		error = fmaster_read(td, fd, p, sizeof(*p));
	}
	if (error != 0)
		return (error);
	if ((*p & 0x80) != 0)
		return (EMSGSIZE);
	*size = (uintptr_t)p - (uintptr_t)buf + 1;
	return (0);
}

#define	IMPLEMENT_READ_X(type, name, bufsize, decode)		\
int								\
name(struct thread *td, type *dest, int *size)			\
{								\
	int error, fd;						\
	char buf[bufsize];					\
								\
	fd = fmaster_rfd_of_thread(td);				\
	error = read_numeric_sequence(				\
		td,						\
		fd,						\
		buf,						\
		array_sizeof(buf),				\
		size);						\
	if (error != 0)						\
		return (error);					\
								\
	return (decode(buf, *size, dest) != 0 ? EPROTO : 0);	\
}

IMPLEMENT_READ_X(
	int8_t,
	fmaster_read_int8,
	FSYSCALL_BUFSIZE_INT8,
	fsyscall_decode_int8)
IMPLEMENT_READ_X(
	int16_t,
	fmaster_read_int16,
	FSYSCALL_BUFSIZE_INT16,
	fsyscall_decode_int16)
IMPLEMENT_READ_X(
	int32_t,
	fmaster_read_int32,
	FSYSCALL_BUFSIZE_INT32,
	fsyscall_decode_int32)
IMPLEMENT_READ_X(
	int64_t,
	fmaster_read_int64,
	FSYSCALL_BUFSIZE_INT64,
	fsyscall_decode_int64)

int
fmaster_read_payload_size(struct thread *td, payload_size_t *dest)
{
	int _;

	return (fmaster_read_uint32(td, dest, &_));
}

int
fmaster_read_command(struct thread *td, command_t *dest)
{
	int _;

	return (fmaster_read_uint32(td, dest, &_));
}

static int
write_aio(struct thread *td, int d, const void *buf, size_t nbytes, enum uio_seg segflg)
{
	struct uio auio;
	struct iovec aiov;
	int error;

	if (INT_MAX < nbytes)
		return (EINVAL);

	/* Casting to uintptr_t is needed to escape the compiler warning. */
	aiov.iov_base = (void *)(uintptr_t)buf;
	aiov.iov_len = nbytes;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbytes;
	auio.uio_segflg = segflg;

	error = 0;
	while (((error == 0) || (error == EINTR)) && (0 < auio.uio_resid))
		error = kern_writev(td, d, &auio);

	return (error);
}

int
fmaster_write_from_userspace(struct thread *td, int d, const void *buf, size_t nbytes)
{
	return (write_aio(td, d, buf, nbytes, UIO_USERSPACE));
}

int
fmaster_write(struct thread *td, int d, const void *buf, size_t nbytes)
{
	return (write_aio(td, d, buf, nbytes, UIO_SYSSPACE));
}

struct fmaster_data *
fmaster_data_of_thread(struct thread *td)
{
	return ((struct fmaster_data *)(td->td_proc->p_emuldata));
}

int
fmaster_rfd_of_thread(struct thread *td)
{
	return (fmaster_data_of_thread(td)->rfd);
}

int
fmaster_wfd_of_thread(struct thread *td)
{
	return (fmaster_data_of_thread(td)->wfd);
}

struct fmaster_fd *
fmaster_fds_of_thread(struct thread *td)
{
	return (fmaster_data_of_thread(td)->fds);
}

#define	IMPLEMENT_WRITE_X(type, name, bufsize, encode)	\
int							\
name(struct thread *td, type n)				\
{							\
	int len, wfd;					\
	char buf[bufsize];				\
							\
	len = encode(n, buf, array_sizeof(buf));	\
	if (len < 0)					\
		return (EMSGSIZE);			\
	wfd = fmaster_wfd_of_thread(td);		\
	return (fmaster_write(td, wfd, buf, len));	\
}

IMPLEMENT_WRITE_X(
		command_t,
		fmaster_write_command,
		FSYSCALL_BUFSIZE_COMMAND,
		fsyscall_encode_command)
IMPLEMENT_WRITE_X(
		int32_t,
		fmaster_write_int32,
		FSYSCALL_BUFSIZE_INT32,
		fsyscall_encode_int32)

int
fmaster_execute_return_optional32(struct thread *td, command_t expected_cmd, int (*callback)(struct thread *, int, payload_size_t *, void *), void *bonus)
{
	payload_size_t actual_payload_size, optional_payload_size, payload_size;
	command_t cmd;
	int errnum, errnum_len, error, retval, retval_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (expected_cmd != cmd) {
		log(LOG_ERR,
		    "fmaster[%d]: command mismatched: expected=%d, actual=%d\n",
		    td->td_proc->p_pid, expected_cmd, cmd);
		return (EPROTO);
	}
	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);
	error = fmaster_read_int(td, &retval, &retval_len);
	if (error != 0)
		return (error);

	if (retval == -1) {
		error = fmaster_read_int32(td, &errnum, &errnum_len);
		if (error != 0)
			return (error);
		actual_payload_size = retval_len + errnum_len;
		if (payload_size != actual_payload_size) {
			log(LOG_ERR,
			    "fmaster[%d]: payload size mismatched: expected=%d,"
			    " actual=%d\n",
			    td->td_proc->p_pid, payload_size,
			    actual_payload_size);
			return (EPROTO);
		}
		return (errnum);
	}

	error = callback(td, retval, &optional_payload_size, bonus);
	if (error != 0)
		return (error);

	actual_payload_size = retval_len + optional_payload_size;
	if (payload_size != actual_payload_size) {
		log(LOG_ERR,
		    "fmaster[%d]: payload size mismatched: expected=%d, actual="
		    "%d\n",
		    td->td_proc->p_pid, payload_size, actual_payload_size);
		return (EPROTO);
	}

	td->td_retval[0] = retval;

	return (0);
}

int
fmaster_execute_return_generic32(struct thread *td, command_t expected_cmd)
{
	/**
	 * TODO: fmaster_execute_return_generic32 is very similar to
	 * fmaster_execute_return_generic64.
	 */
	int32_t ret;
	command_t cmd;
	uint32_t payload_size;
	int errnum, errnum_len, error, ret_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != expected_cmd)
		return (EPROTO);

	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_int32(td, &ret, &ret_len);
	if (error != 0)
		return (error);
	if (ret != -1) {
		if (payload_size != ret_len)
			return (EPROTO);
		td->td_retval[0] = ret;
		return (0);
	}

	error = fmaster_read_int32(td, &errnum, &errnum_len);
	if (error != 0)
		return (error);
	if (payload_size != ret_len + errnum_len)
		return (EPROTO);
	return (errnum);
}

static int
get_vfd_of_lfd(struct thread *td, enum fmaster_fd_type type, int lfd, int *vfd)
{
	struct fmaster_fd *fd, *fds;
	int i;

	fds = fmaster_fds_of_thread(td);
	for (i = 0; i < FD_NUM; i++) {
		fd = &fds[i];
		if ((fd->fd_type == type) || (fd->fd_local == lfd)) {
			*vfd = i;
			return (0);
		}
	}

	return (EPROTO);
}

int
fmaster_fd_of_master_fd(struct thread *td, int master_fd, int *vfd)
{

	return (get_vfd_of_lfd(td, FD_MASTER, master_fd, vfd));
}

int
fmaster_fd_of_slave_fd(struct thread *td, int slave_fd, int *vfd)
{

	return (get_vfd_of_lfd(td, FD_SLAVE, slave_fd, vfd));
}

int
fmaster_execute_return_generic64(struct thread *td, command_t expected_cmd)
{
	int64_t ret;
	command_t cmd;
	uint32_t payload_size;
	int errnum, errnum_len, error, ret_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != expected_cmd)
		return (EPROTO);

	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_int64(td, &ret, &ret_len);
	if (error != 0)
		return (error);
	if (ret != -1) {
		if (payload_size != ret_len)
			return (EPROTO);
		td->td_retval[0] = ret & UINT32_MAX;
		td->td_retval[1] = ret >> 32;
		return (0);
	}

	error = fmaster_read_int32(td, &errnum, &errnum_len);
	if (error != 0)
		return (error);
	if (payload_size != ret_len + errnum_len)
		return (EPROTO);
	return (errnum);
}

int
fmaster_read_to_userspace(struct thread *td, int d, void *buf, size_t nbytes)
{

	return do_readv(td, d, buf, nbytes, UIO_USERSPACE);
}

static int
find_unused_fd(struct thread *td)
{
	struct fmaster_fd *fds;
	int i;

	fds = fmaster_fds_of_thread(td);
	for (i = 0; (i < FD_NUM) && (fds[i].fd_type != FD_CLOSED); i++);

	return (i);
}

int
fmaster_type_of_fd(struct thread *td, int d, enum fmaster_fd_type *t)
{

	if ((d < 0) || (FD_NUM <= d))
		return (EBADF);

	*t = fmaster_fds_of_thread(td)[d].fd_type;

	return (0);
}

int
fmaster_register_fd_at(struct thread *td, enum fmaster_fd_type type, int d, int at)
{
	struct fmaster_fd *fd;
	const char *fmt = "fmaster[%d]: fd %d on %s has been registered as fd %"
			  "d\n";
	const char *side;

	fd = &fmaster_fds_of_thread(td)[at];
	fd->fd_type = type;
	fd->fd_local = d;

	side = type == FD_SLAVE ? "slave" : "master";
	log(LOG_DEBUG, fmt, td->td_proc->p_pid, d, side, at);

	return (0);
}

int
fmaster_register_fd(struct thread *td, enum fmaster_fd_type type, int d, int *virtual_fd)
{

	*virtual_fd = find_unused_fd(td);
	if (*virtual_fd == FD_NUM)
		return (EMFILE);

	return (fmaster_register_fd_at(td, type, d, *virtual_fd));
}

int
fmaster_return_fd(struct thread *td, enum fmaster_fd_type type, int d)
{
	int error, virtual_fd;

	error = fmaster_register_fd(td, type, d, &virtual_fd);
	if (error != 0)
		return (error);

	td->td_retval[0] = virtual_fd;

	return (0);
}

void
fmaster_close_fd(struct thread *td, int d)
{
	fmaster_fds_of_thread(td)[d].fd_type = FD_CLOSED;
}

static int
execute_accept_call(struct thread *td, command_t call_command, int s,
		    socklen_t namelen)
{
	struct payload *payload;
	payload_size_t payload_size;
	int error, wfd;
	const char *buf;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);

	error = fsyscall_payload_add_int(payload, s);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_socklen(payload, namelen);
	if (error != 0)
		goto exit;

	error = fmaster_write_command(td, call_command);
	if (error != 0)
		goto exit;
	payload_size = fsyscall_payload_get_size(payload);
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		goto exit;
	wfd = fmaster_wfd_of_thread(td);
	buf = fsyscall_payload_get(payload);
	error = fmaster_write(td, wfd, buf, payload_size);
	if (error != 0)
		goto exit;

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
execute_accept_return(struct thread *td, command_t return_command,
		      struct sockaddr_storage *addr, socklen_t *namelen)
{
	payload_size_t actual_payload_size, payload_size;
	command_t cmd;
	int addr_len, errnum, errnum_len, error, namelen_len, retval;
	int retval_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != return_command)
		return (EPROTO);

	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_int(td, &retval, &retval_len);
	if (error != 0)
		return (error);
	actual_payload_size = retval_len;
	if (retval == -1) {
		error = fmaster_read_int(td, &errnum, &errnum_len);
		if (error != 0)
			return (error);
		actual_payload_size += errnum_len;
		if (payload_size != actual_payload_size)
			return (EPROTO);
		return (errnum);
	}

	error = fmaster_read_socklen(td, namelen, &namelen_len);
	if (error != 0)
		return (error);
	actual_payload_size += namelen_len;
	error = fmaster_read_sockaddr(td, addr, &addr_len);
	if (error != 0)
		return (error);
	actual_payload_size += addr_len;
	if (payload_size != actual_payload_size)
		return (EPROTO);
	td->td_retval[0] = retval;

	return (0);
}

static int
accept_main(struct thread *td, command_t call_command, command_t return_command,
	    int s, struct sockaddr *name, socklen_t *namelen)
{
	struct sockaddr_storage addr;
	socklen_t actual_namelen, knamelen, len;
	int error, fd;

	error = copyin(namelen, &knamelen, sizeof(knamelen));
	if (error != 0)
		return (error);
	fd = fmaster_fds_of_thread(td)[s].fd_local;
	error = execute_accept_call(td, call_command, fd, knamelen);
	if (error != 0)
		return (error);
	error = execute_accept_return(td, return_command, &addr,
				      &actual_namelen);
	if (error != 0)
		return (error);
	len = MIN(MIN(sizeof(addr), knamelen), actual_namelen);
	error = copyout(&addr, name, len);
	if (error != 0)
		return (error);
	error = copyout(&actual_namelen, namelen, sizeof(actual_namelen));
	if (error != 0)
		return (error);

	return (0);
}

int
fmaster_execute_accept_protocol(struct thread *td, const char *command,
				command_t call_command,
				command_t return_command, int s,
				struct sockaddr *name, socklen_t *namelen)
{
	struct timeval time_start;
	int error;
	const char *fmt = "fmaster[%d]: %s: started: s=%d, name=%p, namelen=%p"
			  "\n";

	log(LOG_DEBUG, fmt, td->td_proc->p_pid, command, s, name, namelen);
	microtime(&time_start);

	error = accept_main(td, call_command, return_command, s, name, namelen);

	fmaster_log_syscall_end(td, command, &time_start, error);

	return (error);
}

static int
execute_connect_call(struct thread *td, command_t call_command, int s,
		     struct sockaddr *name, socklen_t namelen)
{
	struct sockaddr_storage addr;
	struct payload *payload;
	payload_size_t payload_size;
	int error, slave_fd, wfd;
	const char *buf;

	if (sizeof(addr) < namelen)
		return (EINVAL);
	bzero(&addr, sizeof(addr));
	error = copyin(name, &addr, namelen);
	if (error != 0)
		return (error);
	if (addr.ss_family != AF_LOCAL)
		return (EPROTONOSUPPORT);

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);

	slave_fd = fmaster_fds_of_thread(td)[s].fd_local;
	error = fsyscall_payload_add_int32(payload, slave_fd);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_uint32(payload, namelen);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_sockaddr(payload,
					      (struct sockaddr *)&addr);
	if (error != 0)
		goto exit;

	error = fmaster_write_command(td, call_command);
	if (error != 0)
		goto exit;
	payload_size = fsyscall_payload_get_size(payload);
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		goto exit;
	wfd = fmaster_wfd_of_thread(td);
	buf = fsyscall_payload_get(payload);
	error = fmaster_write(td, wfd, buf, payload_size);
	if (error != 0)
		goto exit;

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
connect_main(struct thread *td, command_t call_command,
	     command_t return_command, int s, struct sockaddr *name,
	     socklen_t namelen)
{
	int error;

	error = execute_connect_call(td, call_command, s, name, namelen);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_generic32(td, return_command);
	if (error != 0)
		return (error);

	return (0);
}

int
fmaster_execute_connect_protocol(struct thread *td, const char *command,
				 command_t call_command,
				 command_t return_command, int s,
				 struct sockaddr *name, socklen_t namelen)
{
	struct timeval time_start;
	int error;
	const char *fmt = "fmaster[%d]: %s: started: s=%d, name=%p, namelen=%d"
			  "\n";

	log(LOG_DEBUG, fmt, td->td_proc->p_pid, command, s, name, namelen);
	microtime(&time_start);

	error = connect_main(td, call_command, return_command, s, name,
			     namelen);

	fmaster_log_syscall_end(td, command, &time_start, error);

	return (error);
}

static int
kevent_copyin(void *arg, struct kevent *kevp, int count)
{
	struct kevent *kev;

	if (1 < count)
		return (EINVAL);

	kev = (struct kevent *)arg;
	memcpy(kevp, kev, sizeof(*kev) * count);

	return (0);
}

int
fmaster_initialize_kqueue(struct thread *td, struct fmaster_data *data)
{
	struct kevent kev;
	struct kevent_copyops k_ops;
	pid_t pid;
	int error, kq;
	u_short flags;

	pid = td->td_proc->p_pid;
	error = sys_kqueue(td, NULL);
	if (error != 0) {
		log(LOG_DEBUG, "fmaster[%d]: sys_kqueue failed: error=%d\n",
		    pid, error);
		return (error);
	}
	kq = td->td_retval[0];

	flags = EV_ADD | EV_ENABLE | EV_CLEAR;
	EV_SET(&kev, data->rfd, EVFILT_READ, flags, 0, 0, NULL);
	k_ops.arg = &kev;
	k_ops.k_copyout = NULL;
	k_ops.k_copyin = kevent_copyin;
	error = kern_kevent(td, kq, 1, 0, &k_ops, NULL);
	if (error != 0) {
		log(LOG_DEBUG, "fmaster[%d]: kern_kevent failed: error=%d\n",
		    pid, error);
		return (error);
	}

	data->kq = kq;
	data->rfdlen = 0;

	return (0);
}

static int
socket(struct thread *td, int *sock)
{
	struct socket_args args;
	int error;

	args.domain = PF_LOCAL;
	args.type = SOCK_STREAM;
	args.protocol = 0;
	error = sys_socket(td, &args);
	if (error != 0)
		return (error);

	*sock = td->td_retval[0];

	return (0);
}

#define SUN_LEN(su) \
	(sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))

static int
connect(struct thread *td, int sock)
{
	struct sockaddr_storage addr;
	struct sockaddr_un *paddr;
	int error;
	const char *path;

	paddr = (struct sockaddr_un *)&addr;
	paddr->sun_family = AF_LOCAL;
	path = fmaster_data_of_thread(td)->fork_sock;
	error = copystr(path, paddr->sun_path, sizeof(paddr->sun_path), NULL);
	if (error != 0)
		return (error);
	paddr->sun_len = SUN_LEN(paddr);

	error = kern_connect(td, sock, (struct sockaddr *)paddr);
	if (error != 0)
		return (error);

	return (0);
}

static int
connect_to_mhub(struct thread *td)
{
	struct fmaster_data *data;
	int error, pidlen, sock;
	char buf[FSYSCALL_BUFSIZE_PID];

	error = socket(td, &sock);
	if (error != 0)
		return (error);
	error = connect(td, sock);
	if (error != 0)
		return (error);

	data = fmaster_data_of_thread(td);
	data->rfd = data->wfd = sock;
	error = fmaster_initialize_kqueue(td, data);
	if (error != 0)
		return (error);

	error = fmaster_write(td, sock, data->token, data->token_size);
	if (error != 0)
		return (error);
	pidlen = fsyscall_encode_pid(td->td_proc->p_pid, buf, sizeof(buf));
	if (pidlen < 0)
		return (ENOMEM);
	error = fmaster_write(td, sock, buf, pidlen);
	if (error != 0)
		return (error);

	return (0);
}

void
fmaster_schedtail(struct thread *td)
{
	int error;
	const char *fmt = "fmaster[%d]: cannot connect to mhub: error=%d\n";

	error = connect_to_mhub(td);
	if (error != 0)
		log(LOG_ERR, fmt, td->td_proc->p_pid, error);
}

const char *
fmaster_get_sockopt_name(int optname)
{
	switch (optname) {
	case SO_DEBUG:
		return "SO_DEBUG";
	case SO_ACCEPTCONN:
		return "SO_ACCEPTCONN";
	case SO_REUSEADDR:
		return "SO_REUSEADDR";
	case SO_KEEPALIVE:
		return "SO_KEEPALIVE";
	case SO_DONTROUTE:
		return "SO_DONTROUTE";
	case SO_BROADCAST:
		return "SO_BROADCAST";
	case SO_USELOOPBACK:
		return "SO_USELOOPBACK";
	case SO_LINGER:
		return "SO_LINGER";
	case SO_OOBINLINE:
		return "SO_OOBINLINE";
	case SO_REUSEPORT:
		return "SO_REUSEPORT";
	case SO_TIMESTAMP:
		return "SO_TIMESTAMP";
	case SO_NOSIGPIPE:
		return "SO_NOSIGPIPE";
	case SO_ACCEPTFILTER:
		return "SO_ACCEPTFILTER";
	case SO_BINTIME:
		return "SO_BINTIME";
	case SO_NO_OFFLOAD:
		return "SO_NO_OFFLOAD";
	case SO_NO_DDP:
		return "SO_NO_DDP";
	case SO_SNDBUF:
		return "SO_SNDBUF";
	case SO_RCVBUF:
		return "SO_RCVBUF";
	case SO_SNDLOWAT:
		return "SO_SNDLOWAT";
	case SO_RCVLOWAT:
		return "SO_RCVLOWAT";
	case SO_SNDTIMEO:
		return "SO_SNDTIMEO";
	case SO_RCVTIMEO:
		return "SO_RCVTIMEO";
	case SO_ERROR:
		return "SO_ERROR";
	case SO_TYPE:
		return "SO_TYPE";
	case SO_LABEL:
		return "SO_LABEL";
	case SO_PEERLABEL:
		return "SO_PEERLABEL";
	case SO_LISTENQLIMIT:
		return "SO_LISTENQLIMIT";
	case SO_LISTENQLEN:
		return "SO_LISTENQLEN";
	case SO_LISTENINCQLEN:
		return "SO_LISTENINCQLEN";
	case SO_SETFIB:
		return "SO_SETFIB";
	case SO_USER_COOKIE:
		return "SO_USER_COOKIE";
	case SO_PROTOCOL:
	/* case SO_PROTOTYPE: */
		return "SO_PROTOCOL";
	default:
		break;
	}

	return "unknown option";
}

void
fmaster_chain_flags(char *buf, size_t bufsize, flag_t flags, struct flag_definition defs[], size_t ndefs)
{
	int i, len, size;
	const char *sep;

	buf[0] = '\0';
	len = 0;
	sep = "";
	for (i = 0; i < ndefs; i++) {
		if ((flags & defs[i].value) == 0)
			continue;
		size = bufsize - len;
		len += snprintf(&buf[len], size, "%s%s", sep, defs[i].name);
		sep = "|";
	}
	if (buf[0] == '\0')
		snprintf(buf, bufsize, "nothing");
}

/**
 * Writes a payload with its size.
 */
static int
fmaster_write_payload(struct thread *td, struct payload *payload)
{
	int error, wfd;
	payload_size_t payload_size;
	const char *buf;

	payload_size = fsyscall_payload_get_size(payload);
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		return (error);
	wfd = fmaster_wfd_of_thread(td);
	buf = fsyscall_payload_get(payload);
	error = fmaster_write(td, wfd, buf, payload_size);
	if (error != 0)
		return (error);

	return (0);
}

int
fmaster_write_payloaded_command(struct thread *td, command_t cmd,
				struct payload *payload)
{
	int error;

	error = fmaster_write_command(td, cmd);
	if (error != 0)
		return (error);
	error = fmaster_write_payload(td, payload);
	if (error != 0)
		return (error);

	return (0);
}

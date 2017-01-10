#include <sys/param.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/malloc_or_die.h>

struct io_ops {
	ssize_t	(*op_read)(struct io *, void *, size_t);
	ssize_t	(*op_write)(struct io *, void *, size_t);
	int	(*op_get_rfd)(const struct io *);
	int	(*op_get_wfd)(const struct io *);
	void	(*op_set_readable)(struct io *);
	bool	(*op_is_readable)(const struct io *);
	int	(*op_close)(struct io *);

	void	(*op_dump)(const struct io *, char *, size_t);
};

#define	io_ssl		u.ssl
#define	io_rfd		u.plain.rfd
#define	io_wfd		u.plain.wfd
#define	io_readable	u.plain.readable

/*******************************************************************************
 * plain operations
 */

static int
close_nossl(struct io *io)
{
	int rfd, wfd;

	rfd = io->io_rfd;
	wfd = io->io_wfd;

	if ((rfd != -1) && (close(rfd) == -1)) {
		io->io_error = errno;
		return (-1);
	}
	if ((wfd != -1) && (rfd != wfd))
		if (close(wfd) == -1) {
			io->io_error = errno;
			return (-1);
		}

	io->io_rfd = io->io_wfd = -1;

	return (0);
}

static void
dump_nossl(const struct io *io, char *str, size_t size)
{

	snprintf(str, size,
		 "io(io_rfd=%d, io_wfd=%d, io_readable=%s, io_error=%d)",
		 io->io_rfd, io->io_wfd, io->io_readable ? "true" : "false",
		 io->io_error);
}

static void
set_readable_nossl(struct io *io)
{

	io->io_readable = true;
}

static bool
is_readable_nossl(const struct io *io)
{

	return (io->io_readable);
}

static int
get_rfd_nossl(const struct io *io)
{

	return (io->io_rfd);
}

static int
get_wfd_nossl(const struct io *io)
{

	return (io->io_wfd);
}

static ssize_t
read_nossl(struct io *io, void *buf, size_t nbytes)
{
	ssize_t n;

	n = read(io->io_rfd, buf, nbytes);
	if (n == -1)
		io->io_error = errno;

	io->io_readable = false;

	return (n);
}

static ssize_t
write_nossl(struct io *io, void *buf, size_t nbytes)
{
	ssize_t n;

	n = write(io->io_wfd, buf, nbytes);
	if (n == -1)
		io->io_error = errno;

	return (n);
}

static struct io_ops ops_nossl = {
	.op_read = read_nossl,
	.op_write = write_nossl,
	.op_get_rfd = get_rfd_nossl,
	.op_get_wfd = get_wfd_nossl,
	.op_set_readable = set_readable_nossl,
	.op_is_readable = is_readable_nossl,
	.op_close = close_nossl,
	.op_dump = dump_nossl
};

void
io_init_nossl(struct io *io, int rfd, int wfd)
{

	io->io_rfd = rfd;
	io->io_wfd = wfd;
	io->io_readable = false;
	io->io_ops = &ops_nossl;
	io->io_error = 0;
}

/*******************************************************************************
 * SSL/TLS operations
 */

static int
close_ssl(struct io *io)
{
	SSL *ssl;

	ssl = io->io_ssl;
	SSL_shutdown(ssl);
	if (close(SSL_get_fd(ssl)) == -1) {
		io->io_error = errno;
		return (-1);
	}

	io->io_ssl = NULL;

	return (0);
}

static void
dump_ssl(const struct io *io, char *str, size_t size)
{

	snprintf(str, size,
		 "io(io->io_ssl=0x%p, io->io_error=%d)",
		 io->io_ssl, io->io_error);
}

static void
set_readable_ssl(struct io *io)
{
	/* nothing */
}

static bool
is_readable_ssl(const struct io *io)
{
	SSL *ssl;

	ssl = io->io_ssl;
	SSL_read(ssl, NULL, 0);

	return (0 < SSL_pending(ssl));
}

static int
get_fd_ssl(const struct io *io)
{

	return (SSL_get_fd(io->io_ssl));
}

static ssize_t
read_ssl(struct io *io, void *buf, size_t nbytes)
{
	int n;

	n = SSL_read(io->io_ssl, buf, nbytes);
	if (n < 0)
		io->io_error = EIO;	/* FIXME */

	return (n);
}

static ssize_t
write_ssl(struct io *io, void *buf, size_t nbytes)
{
	int n;

	n = SSL_write(io->io_ssl, buf, nbytes);
	if (n < 0)
		io->io_error = EIO;	/* FIXME */

	return (n);
}

static struct io_ops ops_ssl = {
	.op_read = read_ssl,
	.op_write = write_ssl,
	.op_get_rfd = get_fd_ssl,
	.op_get_wfd = get_fd_ssl,
	.op_set_readable = set_readable_ssl,
	.op_is_readable = is_readable_ssl,
	.op_close = close_ssl,
	.op_dump = dump_ssl
};

void
io_init_ssl(struct io *io, SSL *ssl)
{
	int fd, flags;

	fd = SSL_get_fd(ssl);
	if (fd == -1) {
		syslog(LOG_ERR, "cannot SSL_get_fd(3)");
		return;
	}
	flags = fcntl(fd, F_GETFL);
	if (fcntl(fd, F_SETFL, O_NONBLOCK | flags) == -1) {
		syslog(LOG_ERR, "cannot fcntl(2): fd=%d", fd);
		return;
	}

	io->io_ssl = ssl;
	io->io_ops = &ops_ssl;
	io->io_error = 0;
}

/******************************************************************************/

int
io_get_rfd(const struct io *io)
{

	return (io->io_ops->op_get_rfd(io));
}

int
io_get_wfd(const struct io *io)
{

	return (io->io_ops->op_get_wfd(io));
}

int
io_close(struct io *io)
{

	return (io->io_ops->op_close(io));
}

bool
io_is_readable(const struct io *io)
{

	return (io->io_ops->op_is_readable(io));
}

void
io_dump(const struct io *io, char *str, size_t size)
{

	io->io_ops->op_dump(io, str, size);
}

int
io_select(int nio, struct io *const *ios, struct timeval *timeout, int *error)
{
	struct io *io;
	fd_set fds;
	int fd, i, maxfd, n, nout;

	if (nio == 0)
		return (0);
	for (i = 0; i < nio; i++)
		if (io_is_readable(ios[i]))
			return (1);

	for (;;) {
		FD_ZERO(&fds);
		maxfd = -1;
		for (i = 0; i < nio; i++) {
			io = ios[i];
			fd = io->io_ops->op_get_rfd(io);
			FD_SET(fd, &fds);
			maxfd = maxfd < fd ? fd : maxfd;
		}
		n = select(maxfd + 1, &fds, NULL, NULL, timeout);
		if (n == -1) {
			*error = errno;
			return (-1);
		}
		if (n == 0)
			return (0);
		nout = 0;
		for (i = 0; i < nio; i++) {
			io = ios[i];
			fd = io->io_ops->op_get_rfd(io);
			if (!FD_ISSET(fd, &fds))
				continue;
			io->io_ops->op_set_readable(io);
			if (io_is_readable(io))
				nout++;
		}
		if (0 < nout)
			return (nout);
	}
}

static int
wait_data(struct io *io, struct timeval *timeout)
{
	int n, error;

	n = io_select(1, &io, timeout, &error);
	if (n == -1) {
		io->io_error = error;
		return (-1);
	}
	if (n == 0) {
		io->io_error = ETIMEDOUT;
		return (-1);
	}
	assert(n == 1);

	return (0);
}

void
write_or_die(struct io *io, const void *buf, size_t nbytes)
{
	size_t n = 0;
	ssize_t m;
	char s[256];

#if 0
	syslog(LOG_DEBUG, "write: nbytes=%lu", nbytes);
	int i;
	for (i = 0; i < nbytes; i++) {
		char *p = (char *)buf;
		int n = 0xff & p[i];
		char c = isprint(n) ? n : ' ';
		syslog(LOG_DEBUG, "write: buf[%d]=0x%02x (%c)", i, n, c);
	}
#endif

	while (n < nbytes) {
		m = io->io_ops->op_write(io, (char *)buf + n, nbytes - n);
		if (m < 0) {
			/*
			 * For more about design information, please read the
			 * comment in ignore_sigpipe() in fshub/main.c. The
			 * comment tells why here ignores EPIPE.
			 */
			if (io->io_error == EPIPE)
				return;
			io->io_ops->op_dump(io, s, sizeof(s));
			die(-1, "cannot write to %s", s);
		}
		n += m;
	}
}

int
io_read_all(struct io *io, void *buf, payload_size_t nbytes)
{
	struct timeval timeout;
	size_t n = 0;
	ssize_t m;

	timeout.tv_sec = 8;	/* Caller must give this. */
	timeout.tv_usec = 0;

	while (n < nbytes) {
		if (wait_data(io, &timeout) == -1) {
			if (io->io_error != EINTR)
				return (-1);
			continue;
		}

		m = io->io_ops->op_read(io, (char *)buf + n, nbytes - n);
		if (m == 0) {
			io->io_error = EPIPE;
			return (-1);
		}
		if (m < 0)
			return (-1);
		n += m;
	}

	return (0);
}

#define	IMPLEMENT_WRITE_X(type, name, bufsize, encode)	\
void							\
name(struct io *io, type n)				\
{							\
	int len;					\
	char buf[bufsize];				\
							\
	len = encode(n, buf, array_sizeof(buf));	\
	write_or_die(io, buf, len);			\
}

IMPLEMENT_WRITE_X(
		command_t,
		write_command,
		FSYSCALL_BUFSIZE_COMMAND,
		encode_command)
IMPLEMENT_WRITE_X(
		payload_size_t,
		write_payload_size,
		FSYSCALL_BUFSIZE_PAYLOAD_SIZE,
		encode_payload_size)
IMPLEMENT_WRITE_X(int32_t, write_int32, FSYSCALL_BUFSIZE_INT32, encode_int32)
IMPLEMENT_WRITE_X(int64_t, write_int64, FSYSCALL_BUFSIZE_INT64, encode_int64)
IMPLEMENT_WRITE_X(
		uint64_t,
		write_uint64,
		FSYSCALL_BUFSIZE_UINT64,
		encode_uint64)

int
io_read_numeric_sequence(struct io *io, char *buf, payload_size_t bufsize)
{
	int nbytes, pos;

	pos = 0;
	nbytes = sizeof(buf[0]);
	if (io_read_all(io, &buf[pos], nbytes) == -1)
		return (-1);
	while ((buf[pos] & 0x80) != 0) {
		pos++;
		assert(pos < bufsize);
		if (io_read_all(io, &buf[pos], nbytes) == -1)
			return (-1);
	}

	return (pos + 1);
}

#define	IMPLEMENT_READ_X(type, name, bufsize, decode)			\
int									\
name(struct io *io, type *n, payload_size_t *len)			\
{									\
	payload_size_t size;						\
	char buf[bufsize];						\
									\
	size = io_read_numeric_sequence(io, buf, array_sizeof(buf));	\
	if (size == -1)							\
		return (-1);						\
	*n = decode(buf, size);						\
	*len = size;							\
									\
	return (0);							\
}

IMPLEMENT_READ_X(int8_t, io_read_int8, FSYSCALL_BUFSIZE_INT8, decode_int8)
IMPLEMENT_READ_X(int16_t, io_read_int16, FSYSCALL_BUFSIZE_INT16, decode_int16)
IMPLEMENT_READ_X(int32_t, io_read_int32, FSYSCALL_BUFSIZE_INT32, decode_int32)
IMPLEMENT_READ_X(int64_t, io_read_int64, FSYSCALL_BUFSIZE_INT64, decode_int64)

#define	IMPLEMENT_READ_WITHOUT_LEN_X(type, name, bufsize, decode)	\
int									\
name(struct io *io, type *n)						\
{									\
	int len;							\
	char buf[bufsize];						\
									\
	len = io_read_numeric_sequence(io, buf, array_sizeof(buf));	\
	if (len == -1)							\
		return (-1);						\
	*n = decode(buf, len);						\
									\
	return (0);							\
}

IMPLEMENT_READ_WITHOUT_LEN_X(
		command_t,
		io_read_command,
		FSYSCALL_BUFSIZE_COMMAND,
		decode_command)
IMPLEMENT_READ_WITHOUT_LEN_X(
		payload_size_t,
		io_read_payload_size,
		FSYSCALL_BUFSIZE_PAYLOAD_SIZE,
		decode_payload_size)

void
write_pair_id(struct io *io, pair_id_t pair_id)
{
	write_uint64(io, pair_id);
}

int
io_read_pair_id(struct io *io, pair_id_t *pair_id)
{
	payload_size_t _;

	return (io_read_uint64(io, pair_id, &_));
}

int
io_transfer(struct io *src, struct io *dst, uint32_t len)
{
	uint32_t nbytes, rest;
	char buf[1024];

	rest = len;
	while (0 < rest) {
		nbytes = MIN(array_sizeof(buf), rest);
		if (io_read_all(src, buf, nbytes) == -1)
			return (-1);
		write_or_die(dst, buf, nbytes);
		rest -= nbytes;
	}

	return (0);
}

int
io_read_string(struct io *io, char **s, payload_size_t *total_len)
{
	uint64_t len;
	payload_size_t len_len;
	char *ptr;

	if (io_read_uint64(io, &len, &len_len) == -1)
		return (-1);

	ptr = malloc_or_die(len + 1);
	if (io_read_all(io, ptr, len) == -1)
		return (-1);
	ptr[len] = '\0';

	*s = ptr;
	*total_len = len_len + len;

	return (0);
}

int
io_read_sigset(struct io *io, sigset_t *set, payload_size_t *len)
{
	payload_size_t n;
	int i;

	*len = 0;
	for (i = 0; i < _SIG_WORDS; i++) {
		if (io_read_uint32(io, &set->__bits[i], &n) == -1)
			return (-1);
		*len += n;
	}

	return (0);
}

int
io_read_timeval(struct io *io, struct timeval *t, payload_size_t *len)
{
	payload_size_t usec_len, sec_len;

	if (io_read_time(io, &t->tv_sec, &sec_len) == -1)
		return (-1);
	if (io_read_susecond(io, &t->tv_usec, &usec_len) == -1)
		return (-1);

	*len = sec_len + usec_len;

	return (0);
}

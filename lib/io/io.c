#include <sys/param.h>
#include <sys/select.h>
#include <sys/uio.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/malloc_or_die.h>

void
io_init(struct io *io, int fd)
{

	io->io_fd = fd;
}

void
write_or_die(int fd, const void *buf, size_t nbytes)
{
	size_t n = 0;
	ssize_t m;

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
		m = write(fd, (char *)buf + n, nbytes - n);
		if (m < 0) {
			/*
			 * For more about design information, please read the
			 * comment in ignore_sigpipe() in fshub/main.c. The
			 * comment tells why here ignores EPIPE.
			 */
			if (errno == EPIPE)
				return;
			die(-1, "cannot write to fd %d", fd);
		}
		n -= m;
	}
}

int
io_read_all(struct io *io, void *buf, payload_size_t nbytes)
{
	fd_set fds;
	struct timeval timeout;
	size_t n = 0;
	ssize_t m;
	int fd, l;

	timeout.tv_sec = 8;	/* Caller must give this. */
	timeout.tv_usec = 0;

	fd = io->io_fd;
	while (n < nbytes) {
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		l = select(fd + 1, &fds, NULL, NULL, &timeout);
		if (l == -1) {
			if (errno != EINTR)
				die(-1, "select(2) failed");
			continue;
		}
		if (l == 0)
			die_with_message(1, "select(2) timeout");

		m = read(fd, (char *)buf + n, nbytes - n);
		if (m == 0) {
			io->io_error = EPIPE;
			return (-1);
		}
		if (m < 0)
			die(-1, "cannot read fd %d", fd);
		n += m;
	}

	return (0);
}

#define	IMPLEMENT_WRITE_X(type, name, bufsize, encode)	\
void							\
name(int fd, type n)					\
{							\
	int len;					\
	char buf[bufsize];				\
							\
	len = encode(n, buf, array_sizeof(buf));	\
	write_or_die(fd, buf, len);			\
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
write_pair_id(int fd, pair_id_t pair_id)
{
	write_uint64(fd, pair_id);
}

int
io_read_pair_id(struct io *io, pair_id_t *pair_id)
{
	payload_size_t _;

	return (io_read_uint64(io, pair_id, &_));
}

int
io_transfer(struct io *io, int wfd, uint32_t len)
{
	uint32_t nbytes, rest;
	char buf[1024];

	rest = len;
	while (0 < rest) {
		nbytes = MIN(array_sizeof(buf), rest);
		if (io_read_all(io, buf, nbytes) == -1)
			return (-1);
		write_or_die(wfd, buf, nbytes);
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

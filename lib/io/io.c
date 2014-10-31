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
		if (m < 0)
			die(-1, "cannot write to fd %d", fd);
		n -= m;
	}
}

void
read_or_die(int fd, const void *buf, size_t nbytes)
{
	fd_set fds;
	struct timeval timeout;
	size_t n = 0;
	ssize_t m;
	int l;

	timeout.tv_sec = 8;	/* Caller must give this. */
	timeout.tv_usec = 0;

	while (n < nbytes) {
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		l = select(fd + 1, &fds, NULL, NULL, &timeout);
		if (l == -1) {
			if (errno != EINTR)
				die(-1, "select(2) failed");
			continue;
		}
		if (l == 0) {
			die_with_message(1, "select(2) timeout");
		}

		m = read(fd, (char *)buf + n, nbytes - n);
		if (m == 0)
			diex(-1, "end-of-file in reading fd of %d", fd);
		if (m < 0)
			die(-1, "cannot read fd %d", fd);
		n += m;
	}
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
read_numeric_sequence(int fd, char *buf, int bufsize)
{
	int nbytes, pos;

	pos = 0;
	nbytes = sizeof(buf[0]);
	read_or_die(fd, &buf[pos], nbytes);
	while ((buf[pos] & 0x80) != 0) {
		pos++;
		assert(pos < bufsize);
		read_or_die(fd, &buf[pos], nbytes);
	}

	return (pos + 1);
}

#define	IMPLEMENT_READ_X(type, name, bufsize, decode)			\
type									\
name(int fd, int *len)							\
{									\
	char buf[bufsize];						\
									\
	*len = read_numeric_sequence(fd, buf, array_sizeof(buf));	\
	return (decode(buf, *len));					\
}

IMPLEMENT_READ_X(int8_t, read_int8, FSYSCALL_BUFSIZE_INT8, decode_int8)
IMPLEMENT_READ_X(int16_t, read_int16, FSYSCALL_BUFSIZE_INT16, decode_int16)
IMPLEMENT_READ_X(int32_t, read_int32, FSYSCALL_BUFSIZE_INT32, decode_int32)
IMPLEMENT_READ_X(int64_t, read_int64, FSYSCALL_BUFSIZE_INT64, decode_int64)

#define	IMPLEMENT_READ_WITHOUT_LEN_X(type, name, bufsize, decode)	\
type									\
name(int fd)								\
{									\
	int len;							\
	char buf[bufsize];						\
									\
	len = read_numeric_sequence(fd, buf, array_sizeof(buf));	\
	return (decode(buf, len));					\
}

IMPLEMENT_READ_WITHOUT_LEN_X(
		command_t,
		read_command,
		FSYSCALL_BUFSIZE_COMMAND,
		decode_command)
IMPLEMENT_READ_WITHOUT_LEN_X(
		payload_size_t,
		read_payload_size,
		FSYSCALL_BUFSIZE_PAYLOAD_SIZE,
		decode_payload_size)

void
write_pair_id(int fd, pair_id_t pair_id)
{
	write_uint64(fd, pair_id);
}

pair_id_t
read_pair_id(int fd)
{
	int _;
	return (read_uint64(fd, &_));
}

void
transfer(int rfd, int wfd, uint32_t len)
{
	uint32_t nbytes, rest;
	char buf[1024];

	rest = len;
	while (0 < rest) {
		nbytes = MIN(array_sizeof(buf), rest);
		read_or_die(rfd, buf, nbytes);
		write_or_die(wfd, buf, nbytes);
		rest -= nbytes;
	}
}

char *
read_string(int rfd, uint64_t *total_len)
{
	uint64_t len;
	int len_len;
	char *ptr;

	len = read_uint64(rfd, &len_len);
	ptr = malloc_or_die(len + 1);
	read_or_die(rfd, ptr, len);
	ptr[len] = '\0';
	*total_len = len_len + len;

	return (ptr);
}

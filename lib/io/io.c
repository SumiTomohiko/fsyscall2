#include <sys/param.h>
#include <sys/uio.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>

void
write_or_die(int fd, const void *buf, size_t nbytes)
{
	size_t n = 0;
	ssize_t m;

	while (n < nbytes) {
		m = write(fd, (char *)buf + n, nbytes - n);
		if (m < 0)
			die(-1, "Cannot write to fd %d", fd);
		n -= m;
	}
}

void
read_or_die(int fd, const void *buf, size_t nbytes)
{
	size_t n = 0;
	ssize_t m;

	while (n < nbytes) {
		m = read(fd, (char *)buf + n, nbytes - n);
		if (m == 0)
			diex(-1, "End-of-file in reading");
		if (m < 0)
			die(-1, "Cannot read fd %d", fd);
		n -= m;
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
IMPLEMENT_WRITE_X(int32_t, write_int32, FSYSCALL_BUFSIZE_INT32, encode_int32)
IMPLEMENT_WRITE_X(int64_t, write_int64, FSYSCALL_BUFSIZE_INT64, encode_int64)

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
name(int fd)								\
{									\
	type dest;							\
	int len;							\
	char buf[bufsize];						\
									\
	len = read_numeric_sequence(fd, buf, array_sizeof(buf));	\
									\
	if (decode(buf, len, &dest) != 0)				\
		diex(-1, "Invalid numeric sequence");			\
	return (dest);							\
}

IMPLEMENT_READ_X(
		int32_t,
		read_int32,
		FSYSCALL_BUFSIZE_INT32,
		fsyscall_decode_int32)
IMPLEMENT_READ_X(
		int64_t,
		read_int64,
		FSYSCALL_BUFSIZE_INT64,
		fsyscall_decode_int64)
IMPLEMENT_READ_X(
		command_t,
		read_command,
		FSYSCALL_BUFSIZE_COMMAND,
		fsyscall_decode_command)

void
write_pid(int fd, pid_t pid)
{
	write_int32(fd, pid);
}

pid_t
read_pid(int fd)
{
	return (read_int32(fd));
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

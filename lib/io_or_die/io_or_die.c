#include <sys/param.h>
#include <sys/socket.h>
#include <assert.h>

#include <fsyscall/private/command.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/io_or_die.h>
#include <fsyscall/private/malloc_or_die.h>

#define	IMPLEMENTE_READ_FUNC(name, type)		\
type							\
read_##name(int fd, payload_size_t *len)		\
{							\
	struct io io;					\
	type n;						\
							\
	io_init(&io, fd);				\
							\
	if (io_read_##name(&io, &n, len) == -1)		\
		diec(1, io.io_error, "cannot read");	\
							\
	return (n);					\
}

IMPLEMENTE_READ_FUNC(int8, int8_t)
IMPLEMENTE_READ_FUNC(int16, int16_t)
IMPLEMENTE_READ_FUNC(int32, int32_t)
IMPLEMENTE_READ_FUNC(int64, int64_t)
IMPLEMENTE_READ_FUNC(uint8, uint8_t)
IMPLEMENTE_READ_FUNC(uint16, uint16_t)
IMPLEMENTE_READ_FUNC(uint32, uint32_t)
IMPLEMENTE_READ_FUNC(uint64, uint64_t)
IMPLEMENTE_READ_FUNC(short, short)
IMPLEMENTE_READ_FUNC(int, int)
IMPLEMENTE_READ_FUNC(long, long)
IMPLEMENTE_READ_FUNC(ushort, unsigned short)
IMPLEMENTE_READ_FUNC(uint, unsigned int)
IMPLEMENTE_READ_FUNC(ulong, unsigned long)
IMPLEMENTE_READ_FUNC(socklen, socklen_t)
IMPLEMENTE_READ_FUNC(time, time_t)
IMPLEMENTE_READ_FUNC(susecond, suseconds_t)

#define	IMPLEMENTE_READ_FUNC_WITHOUT_SIZE(name, type)	\
type							\
read_##name(int fd)					\
{							\
	struct io io;					\
	type n;						\
							\
	io_init(&io, fd);				\
							\
	if (io_read_##name(&io, &n) == -1)		\
		diec(1, io.io_error, "cannot read");	\
							\
	return (n);					\
}

IMPLEMENTE_READ_FUNC_WITHOUT_SIZE(command, command_t)
IMPLEMENTE_READ_FUNC_WITHOUT_SIZE(pair_id, pair_id_t)
IMPLEMENTE_READ_FUNC_WITHOUT_SIZE(payload_size, payload_size_t)

void
read_or_die(int fd, void *buf, int nbytes)
{
	struct io io;

	io_init(&io, fd);

	if (io_read_all(&io, buf, nbytes) == -1)
		diec(1, io.io_error, "cannot read");
}

int
read_numeric_sequence(int fd, char *buf, int bufsize)
{
	struct io io;
	int len;

	io_init(&io, fd);
	len = io_read_numeric_sequence(&io, buf, bufsize);
	if (len == -1)
		diec(1, io.io_error, "cannot read numeric sequence");

	return (len);
}

void
transfer(int rfd, int wfd, uint32_t len)
{
	struct io io;

	io_init(&io, rfd);
	if (io_transfer(&io, wfd, len) == -1)
		diec(1, io.io_error, "cannot transfer");
}

char *
read_string(int fd, payload_size_t *len)
{
	struct io io;
	char *s;

	io_init(&io, fd);
	if (io_read_string(&io, &s, len) == -1)
		diec(1, io.io_error, "cannot read string");

	return (s);
}

void
read_timeval(int fd, struct timeval *t, payload_size_t *len)
{
	struct io io;

	io_init(&io, fd);
	if (io_read_timeval(&io, t, len) == -1)
		diec(1, io.io_error, "cannot read timeval");
}

void
read_sigset(int fd, sigset_t *set, payload_size_t *len)
{
	struct io io;

	io_init(&io, fd);
	if (io_read_sigset(&io, set, len) == -1)
		diec(1, io.io_error, "cannot read sigset");
}

pid_t
read_pid(int fd, payload_size_t *len)
{
	struct io io;
	pid_t pid;

	io_init(&io, fd);
	if (io_read_pid(&io, &pid, len) == -1)
		diec(1, io.io_error, "cannot read pid");

	return (pid);
}

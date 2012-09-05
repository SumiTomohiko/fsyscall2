#include <sys/types.h>
#include <sys/uio.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>

#include <fsyscall/encode.h>
#include <fsyscall/private.h>

void
write_or_die(int fd, const void *buf, size_t nbytes)
{
	size_t n = 0;
	ssize_t m;

	while (n < nbytes) {
		m = write(fd, (char *)buf + n, nbytes - n);
		if (m < 0)
			err(-1, "Cannot write");
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
			errc(-1, EBADF, "End-of-file reached");
		if (m < 0)
			err(-1, "Cannot read");
		n -= m;
	}
}

void
write_int(int fd, int n)
{
	int len;
	char buf[FSYSCALL_BUFSIZE_INT];

	len = fsyscall_encode_int(n, buf, array_sizeof(buf));
	write_or_die(fd, buf, len);
}

int
read_int(int fd)
{
	int nbytes, pos;
	char buf[FSYSCALL_BUFSIZE_INT];

	pos = 0;
	nbytes = sizeof(buf[0]);
	read_or_die(fd, &buf[pos], nbytes);
	while ((buf[pos] & 0x80) != 0) {
		pos++;
		assert(pos < array_sizeof(buf));
		read_or_die(fd, &buf[pos], nbytes);
	}

	return (fsyscall_decode_int(buf, pos + 1));
}

#include <sys/types.h>
#include <sys/uio.h>
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
send_int(int fd, int n)
{
	int len;
	char buf[FSYSCALL_BUFSIZE_INT];

	len = fsyscall_encode_int(n, buf, array_sizeof(buf));
	write_or_die(fd, buf, len);
}

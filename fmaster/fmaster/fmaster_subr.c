#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/uio.h>

#include <fsyscall/encode.h>
#include <fsyscall/fmaster.h>

void
fmaster_read_or_die(struct thread *td, int d, void *buf, size_t nbytes)
{
	struct uio auio;
	struct iovec aiov;

	/* TODO: Enable here. */
#if 0
	if (INT_MAX < nbytes)
		exit1(td, 1);
#endif
	aiov.iov_base = buf;
	aiov.iov_len = nbytes;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbytes;
	auio.uio_segflg = UIO_SYSSPACE;

	while (0 < auio.uio_resid)
		if (kern_readv(td, d, &auio) != 0)
			/* TODO: Print a friendly message. */
			exit1(td, 1);
}

int
fmaster_read_int2(struct thread *td, int fd, int *len)
{
	int pos, size;
	char buf[FSYSCALL_BUFSIZE_INT];

	pos = 0;
	fmaster_read_or_die(td, fd, &buf[pos], sizeof(buf[0]));
	while ((buf[pos] & 0x80) != 0) {
		pos++;
		/* TODO: assert(pos < array_sizeof(buf)) */
		fmaster_read_or_die(td, fd, &buf[pos], sizeof(buf[0]));
	}
	size = pos + 1;
	if (len != NULL)
		*len = size;

	return (fsyscall_decode_int(buf, size));
}

int
fmaster_read_int(struct thread *td, int fd)
{
	return (fmaster_read_int2(td, fd, NULL));
}

void
fmaster_write_or_die(struct thread *td, int d, void *buf, size_t nbytes)
{
	struct uio auio;
	struct iovec aiov;

	/* TODO: Enable here. */
#if 0
	if (INT_MAX < nbytes)
		exit1(td, 1);
#endif

	aiov.iov_base = buf;
	aiov.iov_len = nbytes;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbytes;
	auio.uio_segflg = UIO_SYSSPACE;

	while (0 < auio.uio_resid)
		if (kern_writev(td, d, &auio) != 0)
			/* TODO: Print a friendly message. */
			exit1(td, 1);
}

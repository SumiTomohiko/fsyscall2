#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/uio.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>

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
fmaster_read_numeric_sequence(struct thread *td, int fd, char *buf, int bufsize)
{
	int pos;

	pos = 0;
	fmaster_read_or_die(td, fd, &buf[pos], sizeof(buf[0]));
	while ((buf[pos] & 0x80) != 0) {
		pos++;
		/* TODO: assert(pos < bufsize). */
		fmaster_read_or_die(td, fd, &buf[pos], sizeof(buf[0]));
	}
	return (pos + 1);
}

int32_t
fmaster_read_int32(struct thread *td, int fd, int *len)
{
	int size;
	char buf[FSYSCALL_BUFSIZE_INT32];

	size = fmaster_read_numeric_sequence(td, fd, buf, array_sizeof(buf));
	if (len != NULL)
		*len = size;

	return (fsyscall_decode_int32(buf, size));
}

command_t
fmaster_read_command(struct thread *td, int fd)
{
	return (fmaster_read_uint32(td, fd, NULL));
}

void
fmaster_write_or_die(struct thread *td, int d, const void *buf, size_t nbytes)
{
	struct uio auio;
	struct iovec aiov;

	/* TODO: Enable here. */
#if 0
	if (INT_MAX < nbytes)
		exit1(td, 1);
#endif

	/* Casting to uintptr_t is needed to escape the compiler warning. */
	aiov.iov_base = (void *)(uintptr_t)buf;
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

static struct master_data *
data_of_thread(struct thread *td)
{
	return ((struct master_data *)(td->td_proc->p_emuldata));
}

int
fmaster_rfd_of_thread(struct thread *td)
{
	return (data_of_thread(td)->rfd);
}

int
fmaster_wfd_of_thread(struct thread *td)
{
	return (data_of_thread(td)->wfd);
}

#define	IMPLEMENT_WRITE_X(type, name, bufsize, encode)		\
void								\
name(struct thread *td, type n)					\
{								\
	int len, wfd;						\
	char buf[bufsize];					\
								\
	len = encode(n, buf, array_sizeof(buf));		\
	wfd = fmaster_wfd_of_thread(td);			\
	return (fmaster_write_or_die(td, wfd, buf, len));	\
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
fmaster_execute_return_generic(struct thread *td, command_t expected_cmd)
{
	command_t cmd;
	uint32_t payload_size;
	int errnum, errnum_len, ret, ret_len, rfd;

	rfd = fmaster_rfd_of_thread(td);
	cmd = fmaster_read_command(td, rfd);
	/* TODO: Assert. */
	if (cmd != expected_cmd)
		return (-1);
	payload_size = fmaster_read_payload_size(td, rfd);
	ret = fmaster_read_uint32(td, rfd, &ret_len);
	if (ret != -1) {
		td->td_retval[0] = ret;
		return (0);
	}
	errnum = fmaster_read_int32(td, rfd, &errnum_len);
	/* TODO: Assert (payload_size == ret_len + errnum_len). */
	return (errnum);
}

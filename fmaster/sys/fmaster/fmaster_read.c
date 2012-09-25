#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/uio.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
execute_call(struct thread *td, struct fmaster_read_args *uap)
{
	int error, fd_len, nbytes_len, wfd;
	char fd_buf[FSYSCALL_BUFSIZE_INT32];
	char nbytes_buf[FSYSCALL_BUFSIZE_UINT64];;

	fd_len = fsyscall_encode_int32(uap->fd, fd_buf, array_sizeof(fd_buf));
	if (fd_len < 0)
		return (EMSGSIZE);
	nbytes_len = fsyscall_encode_uint64(
		uap->nbytes,
		nbytes_buf,
		array_sizeof(nbytes_buf));
	if (nbytes_len < 0)
		return (EMSGSIZE);

	error = fmaster_write_command(td, CALL_READ);
	if (error != 0)
		return (error);
	error = fmaster_write_payload_size(td, fd_len + nbytes_len);
	if (error != 0)
		return (error);

	wfd = fmaster_wfd_of_thread(td);
	error = fmaster_write(td, wfd, fd_buf, fd_len);
	if (error != 0)
		return (error);
	error = fmaster_write(td, wfd, nbytes_buf, nbytes_len);
	if (error != 0)
		return (error);

	return (0);
}

static int
copy_to_userspace(struct thread *td, int d, void *buf, size_t nbytes)
{
	/*
	 * TODO: This was copied and pasted from fmaster_read with a little
	 * change. Share.
	 */
	struct uio auio;
	struct iovec aiov;
	int error;

	aiov.iov_base = buf;
	aiov.iov_len = nbytes;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbytes;
	auio.uio_segflg = UIO_USERSPACE;

	error = 0;
	while ((0 < auio.uio_resid) && (error == 0))
		error = kern_readv(td, d, &auio);
	return (error);
}

static int
execute_return(struct thread *td, void *buf)
{
	int errnum, errnum_len, error, ret_len, rfd;
	command_t cmd;
	ssize_t ret;
	payload_size_t payload_size;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != RET_READ)
		return (EPROTO);

	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_int64(td, &ret, &ret_len);
	if (error != 0)
		return (error);
	td->td_retval[0] = ret;
	if (ret == -1) {
		error = fmaster_read_int32(td, &errnum, &errnum_len);
		if (error != 0)
			return (error);
		if (payload_size != ret_len + errnum_len)
			return (EPROTO);
		return (errnum);
	}
	if (payload_size != ret_len + ret)
		return (EPROTO);
	rfd = fmaster_rfd_of_thread(td);
	return (copy_to_userspace(td, rfd, buf, ret));
}

int
sys_fmaster_read(struct thread *td, struct fmaster_read_args *uap)
{
	int error;

	error = execute_call(td, uap);
	if (error != 0)
		return (error);

	return (execute_return(td, uap->buf));
}

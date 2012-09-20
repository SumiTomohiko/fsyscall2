#include <sys/param.h>
#include <sys/proc.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static void
execute_call(struct thread *td, struct fmaster_write_args *uap)
{
	int fd_len, nbytes_len, payload_size, wfd;
	char fd[FSYSCALL_BUFSIZE_INT32], nbytes[FSYSCALL_BUFSIZE_INT32];

	fd_len = fsyscall_encode_int32(uap->fd, fd, array_sizeof(fd));
	nbytes_len = fsyscall_encode_int32(
		uap->nbytes,
		nbytes,
		array_sizeof(nbytes));
	payload_size = fd_len + nbytes_len + uap->nbytes;

	fmaster_write_command_or_die(td, CALL_WRITE);
	fmaster_write_int32_or_die(td, payload_size);

	wfd = fmaster_wfd_of_thread(td);
	fmaster_write_or_die(td, wfd, fd, fd_len);
	fmaster_write_or_die(td, wfd, nbytes, nbytes_len);
	fmaster_write_or_die(td, wfd, uap->buf, uap->nbytes);
}

static int
execute_return(struct thread *td)
{
	command_t cmd;
	uint32_t payload_size;
	int errnum_len, ret, ret_len, rfd;
	char errnum_buf[FSYSCALL_BUFSIZE_INT32];
	char ret_buf[FSYSCALL_BUFSIZE_INT32];

	rfd = fmaster_rfd_of_thread(td);
	cmd = fmaster_read_command(td, rfd);
	/* TODO: Assert. */
	if (cmd != RET_WRITE)
		return (-1);
	payload_size = fmaster_read_uint32(td, rfd);
	ret_len = fmaster_read_numeric_sequence(
		td,
		rfd,
		ret_buf,
		array_sizeof(ret_buf));
	ret = fsyscall_decode_uint32(ret_buf, ret_len);
	if (ret != -1)
		return (ret);
	errnum_len = fmaster_read_numeric_sequence(
		td,
		rfd,
		errnum_buf,
		array_sizeof(errnum_buf));
	errnum_len = fsyscall_decode_int32(errnum_buf, errnum_len);
	/* TODO: Assert (payload_size == ret_len + errnum_len). */
	/* TODO: Set errno. */
	return (ret);
}

int
sys_fmaster_write(struct thread *td, struct fmaster_write_args *uap)
{
	int ret;

	if ((((size_t)1 << 32) - 1) < uap->nbytes)
		return (-1);

	execute_call(td, uap);
	ret = execute_return(td);

	return (ret);
}

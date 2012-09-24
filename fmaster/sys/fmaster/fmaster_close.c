#include <sys/param.h>
#include <sys/proc.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
execute_close(struct thread *td, struct fmaster_close_args *uap)
{
	int error, fd_buf_len, wfd;
	char fd_buf[FSYSCALL_BUFSIZE_INT32];

	fd_buf_len = fsyscall_encode_int32(
		uap->fd,
		fd_buf,
		array_sizeof(fd_buf));
	if (fd_buf_len < 0)
		return (EMSGSIZE);

	wfd = fmaster_wfd_of_thread(td);
	error = fmaster_write_command(td, CALL_CLOSE);
	if (error != 0)
		return (error);
	error = fmaster_write_payload_size(td, fd_buf_len);
	if (error != 0)
		return (error);
	error = fmaster_write(td, wfd, fd_buf, fd_buf_len);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_close(struct thread *td, struct fmaster_close_args *uap)
{
	int error;

	error = execute_close(td, uap);
	if (error != 0)
		return (error);
	return (fmaster_execute_return_generic(td, RET_CLOSE));
}

#include <sys/param.h>
#include <sys/proc.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static void
execute_close(struct thread *td, struct fmaster_close_args *uap)
{
	int fd_buf_len, wfd;
	char fd_buf[FSYSCALL_BUFSIZE_INT32];

	fd_buf_len = fsyscall_encode_int32(
		uap->fd,
		fd_buf,
		array_sizeof(fd_buf));

	wfd = fmaster_wfd_of_thread(td);
	fmaster_write_command(td, CALL_CLOSE);
	fmaster_write_payload_size(td, fd_buf_len);
	fmaster_write_or_die(td, wfd, fd_buf, fd_buf_len);
}

int
sys_fmaster_close(struct thread *td, struct fmaster_close_args *uap)
{
	execute_close(td, uap);
	return (fmaster_execute_return_generic(td, RET_CLOSE));
}

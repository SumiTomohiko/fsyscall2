#include <sys/param.h>
#include <sys/proc.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_write(struct thread *td, struct fmaster_write_args *uap)
{
	int fd_len, nbytes_len, payload_size, wfd;
	char fd[FSYSCALL_BUFSIZE_INT32], nbytes[FSYSCALL_BUFSIZE_INT32];

	if ((((size_t)1 << 32) - 1) < uap->nbytes)
		return (-1);

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

	return (0);
}

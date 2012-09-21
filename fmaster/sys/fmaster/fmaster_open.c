#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/libkern.h>
#include <sys/proc.h>

#include <fsyscall/private.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static void
execute_call(struct thread *td, struct fmaster_open_args *uap)
{
	uint64_t path_len, path_len_len;
	int fd_len, flags, mode_len, payload_size, wfd;
	char fd_buf[FSYSCALL_BUFSIZE_INT32], mode_buf[FSYSCALL_BUFSIZE_INT32];
	char *path, path_len_buf[FSYSCALL_BUFSIZE_UINT64];

	path = uap->path;
	path_len = strlen(path);
	path_len_len = fsyscall_encode_uint64(
		path_len,
		path_len_buf,
		array_sizeof(path_len_buf));
	flags = uap->flags;
	fd_len = fsyscall_encode_int32(flags, fd_buf, array_sizeof(fd_buf));
	mode_len = (flags & O_CREAT) != 0 ? fsyscall_encode_int32(
		uap->mode,
		mode_buf,
		array_sizeof(mode_buf)) : 0;
	payload_size = path_len_len + path_len + fd_len + mode_len;

	fmaster_write_command_or_die(td, CALL_OPEN);
	fmaster_write_payload_size_or_die(td, payload_size);
	wfd = fmaster_wfd_of_thread(td);
	fmaster_write_or_die(td, wfd, path_len_buf, path_len_len);
	fmaster_write_or_die(td, wfd, path, path_len);
	fmaster_write_or_die(td, wfd, fd_buf, fd_len);
	if ((flags & O_CREAT) != 0)
		fmaster_write_or_die(td, wfd, mode_buf, mode_len);
}

int
sys_fmaster_open(struct thread *td, struct fmaster_open_args *uap)
{
	execute_call(td, uap);
	return (fmaster_execute_return_generic(td, RET_OPEN));
}

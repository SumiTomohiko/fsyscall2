#include <sys/param.h>
#include <sys/proc.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
execute_call(struct thread *td, struct fmaster_access_args *uap)
{
	size_t path_len;
	payload_size_t payload_size;
	int error, flags, flags_len, path_len_len, wfd;
	char flags_buf[FSYSCALL_BUFSIZE_INT32];
	char path_len_buf[FSYSCALL_BUFSIZE_UINT64];
	const char *path;

	path = uap->path;
	path_len = strlen(path);
	path_len_len = fsyscall_encode_uint64(
		path_len,
		path_len_buf,
		array_sizeof(path_len_buf));
	if (path_len_len < 0)
		return (EMSGSIZE);

	flags = uap->flags;
	flags_len = fsyscall_encode_int32(
		flags,
		flags_buf,
		array_sizeof(flags_buf));
	if (flags_len < 0)
		return (EMSGSIZE);

	error = fmaster_write_command(td, CALL_ACCESS);
	if (error != 0)
		return (error);
	payload_size = path_len_len + path_len + flags_len;
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		return (error);
	wfd = fmaster_wfd_of_thread(td);
	error = fmaster_write(td, wfd, path_len_buf, path_len_len);
	if (error != 0)
		return (error);
	error = fmaster_write(td, wfd, path, path_len);
	if (error != 0)
		return (error);
	error = fmaster_write(td, wfd, flags_buf, flags_len);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_access(struct thread *td, struct fmaster_access_args *uap)
{
	int error;

	error = execute_call(td, uap);
	if (error != 0)
		return (error);
	return (fmaster_execute_return_generic(td, RET_ACCESS));
}

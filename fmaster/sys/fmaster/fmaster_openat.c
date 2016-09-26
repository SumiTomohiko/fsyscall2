#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

/*******************************************************************************
 * the code for masters
 */

/* nothing */

/*******************************************************************************
 * the code for slaves
 */

static int
execute_call(struct thread *td, int lfd, char *path, int flags, mode_t mode)
{
	struct payload *payload;
	int error;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);
	error = fsyscall_payload_add_int(payload, lfd);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_string(payload, path);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_int(payload, flags);
	if (error != 0)
		goto exit;
	if ((flags & O_CREAT) != 0) {
		error = fsyscall_payload_add_mode(payload, mode);
		if (error != 0)
			goto exit;
	}

	error = fmaster_write_payloaded_command(td, OPENAT_CALL, payload);
	if (error != 0)
		goto exit;

	error = 0;
exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
openat_slave(struct thread *td, int lfd, char *path, int flags, mode_t mode)
{
	int error;

	error = execute_call(td, lfd, path, ~O_CLOEXEC & flags, mode);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_generic32(td, OPENAT_RETURN);
	if (error != 0)
		return (error);

	return (0);
}

/*******************************************************************************
 * the entry point
 */

static int
fmaster_openat_main(struct thread *td, int fd, char *path, int flags,
		    mode_t mode)
{
	enum fmaster_file_place place;
	int error, lfd;
	char desc[VNODE_DESC_LEN];

	if ((path[0] == '/') || (fd == AT_FDCWD)) {
		error = fmaster_open(td, "openat (open emulated)", path, flags,
				     mode);
		return (error);
	}

	error = fmaster_get_vnode_info(td, fd, &place, &lfd);
	if (error != 0)
		return (error);
	switch (place) {
	case FFP_MASTER:
		/*
		 * I do not like to allow slaves to list directory entries in
		 * masters. If someone needs it, call kern_open().
		 */
		error = EINVAL;
		break;
	case FFP_SLAVE:
		error = openat_slave(td, lfd, path, flags, mode);
		break;
	case FFP_PENDING_SOCKET:
	default:
		error = EINVAL;
		break;
	}
	if (error != 0)
		return (error);

	snprintf(desc, sizeof(desc), "openat for fd=%d, path=%s", fd, path);
	error = fmaster_return_fd(td, DTYPE_VNODE, place, td->td_retval[0],
				  desc);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_openat(struct thread *td, struct fmaster_openat_args *uap)
{
	struct timeval time_start;
	mode_t mode;
	int error, fd, flags;
	const char *sysname = "openat";
	char path[MAXPATHLEN];

	error = copyinstr(uap->path, path, sizeof(path), NULL);
	if (error != 0) {
		fmaster_log(td, LOG_ERR,
			    "%s: cannot copyinstr path: error=%d",
			    sysname, error);
		return (error);
	}

	fd = uap->fd;
	flags = uap->flag;
	mode = uap->mode;
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: fd=%d, path=\"%s\", flags=0x%x, mode=0o%o",
		    sysname, fd, path, flags, mode);
	microtime(&time_start);

	error = fmaster_openat_main(td, fd, path, flags, mode);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

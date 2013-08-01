#include <sys/param.h>
#include <sys/types.h>
#include <sys/libkern.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_dup_pre_execute(struct thread *td, struct fmaster_dup_args *uap, int *error)
{
	struct dup_args args;
	enum fmaster_fd_type type;
	int fd;

	fd = uap->fd;
	if (fmaster_type_of_fd(td, fd) != FD_MASTER) {
		*error = EBADF;
		return (0);
	}

	args.fd = fmaster_fds_of_thread(td)[fd].local_fd;
	*error = sys_dup(td, &args);
	if (*error != 0)
		return (0);

	return (fmaster_return_fd(td, FD_MASTER, td->td_retval[0]));
}

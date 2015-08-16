#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/proc.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_fcntl_pre_execute(struct thread *td, struct fmaster_fcntl_args *uap,
			  int *error)
{
	bool b;

	if (uap->cmd != F_SETFD)
		return (1);

	b = (uap->arg & FD_CLOEXEC) != 0 ? true : false;
	*error = fmaster_set_close_on_exec(td, uap->fd, b);

	return (0);
}

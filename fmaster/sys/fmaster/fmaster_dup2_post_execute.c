#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_dup2_post_execute(struct thread *td, struct fmaster_dup2_args *uap)
{
	int d = uap->to;

	/*
	 * FIXME: If the file descriptor uap->to is open, this function must
	 * close it.
	 */
	return fmaster_register_fd_at(td, FD_SLAVE, d, d);
}

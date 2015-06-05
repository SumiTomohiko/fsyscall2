#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_kqueue_post_execute(struct thread *td, struct fmaster_kqueue_args *uap)
{
	return fmaster_return_fd(td, FD_MASTER, td->td_retval[0]);
}

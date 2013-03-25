#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_open_post_execute(struct thread *td, struct fmaster_open_args *uap)
{
	return fmaster_return_fd(td, SLAVE_FD2FD(td->td_retval[0]));
}

#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_getpid_post_execute(struct thread *td, struct fmaster_getpid_args *uap)
{

	fmaster_set_slave_pid(td, td->td_retval[0]);

	return (0);
}

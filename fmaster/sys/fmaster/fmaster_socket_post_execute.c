#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_socket_post_execute(struct thread *td, struct fmaster_socket_args *uap)
{

	return (fmaster_return_fd(td, FFP_SLAVE, td->td_retval[0], "socket"));
}

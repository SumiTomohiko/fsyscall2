#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_close_post_common(struct thread *td, struct fmaster_close_args *uap)
{
	fmaster_close_fd(td, uap->fd);
	return (0);
}

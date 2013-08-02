#include <sys/param.h>
#include <sys/syslog.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_dup_post_common(struct thread *td, struct fmaster_dup_args *uap)
{
	enum fmaster_fd_type type = fmaster_type_of_fd(td, uap->fd);

	log(LOG_DEBUG, "fmaster_dup_post_common(td, uap)");
	return (fmaster_return_fd(td, type, td->td_retval[0]));
}

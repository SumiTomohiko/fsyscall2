#include <sys/param.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_kqueue_post_execute(struct thread *td, struct fmaster_kqueue_args *uap)
{
	char desc[VNODE_DESC_LEN];

	snprintf(desc, sizeof(desc), "kqueue (%ld)", td->td_retval[0]);

	return fmaster_return_fd(td, FFP_MASTER, td->td_retval[0], desc);
}

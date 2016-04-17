#include <sys/param.h>
#include <sys/file.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_kqueue_post_execute(struct thread *td, struct fmaster_kqueue_args *uap)
{
	register_t fd;
	char desc[VNODE_DESC_LEN];

	fd = td->td_retval[0];
	snprintf(desc, sizeof(desc), "kqueue (%ld)", fd);

	return (fmaster_return_fd(td, DTYPE_KQUEUE, FFP_MASTER, fd, desc));
}

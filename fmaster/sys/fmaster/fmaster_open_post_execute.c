#include <sys/param.h>
#include <sys/file.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_open_post_execute(struct thread *td, struct fmaster_open_args *uap)
{
	int error;
	short type;
	char desc[VNODE_DESC_LEN], path[VNODE_DESC_LEN];

	error = copyinstr(uap->path, path, sizeof(path), NULL);
	if (error != 0)
		return (error);
	snprintf(desc, sizeof(desc), "open in slave (\"%s\")", path);

	type = DTYPE_VNODE;
	return (fmaster_return_fd(td, type, FFP_SLAVE, td->td_retval[0], desc));
}

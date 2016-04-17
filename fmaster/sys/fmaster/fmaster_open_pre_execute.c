#include <sys/param.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/libkern.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

static int
open_master(struct thread *td, struct fmaster_open_args *uap)
{
	enum fmaster_file_place place;
	int error;
	short type;
	char desc[VNODE_DESC_LEN], path[VNODE_DESC_LEN];

	error = sys_open(td, (struct open_args *)uap);
	if (error != 0)
		return (error);

	error = copyinstr(uap->path, path, sizeof(path), NULL);
	if (error != 0)
		return (error);
	snprintf(desc, sizeof(desc), "open in master (\"%s\")", path);

	type = DTYPE_VNODE;
	place = FFP_MASTER;

	return (fmaster_return_fd(td, type, place, td->td_retval[0], desc));
}

enum fmaster_pre_execute_result
fmaster_open_pre_execute(struct thread *td, struct fmaster_open_args *uap,
			 int *error)
{

	if (fmaster_is_master_file(td, uap->path)) {
		*error = open_master(td, uap);
		return (PRE_EXEC_END);
	}

	return (PRE_EXEC_CONT);
}

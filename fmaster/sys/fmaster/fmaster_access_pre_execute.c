#include <sys/param.h>
#include <sys/types.h>
#include <sys/libkern.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

enum fmaster_pre_execute_result
fmaster_access_pre_execute(struct thread *td, struct fmaster_access_args *uap, int *error)
{

	if (fmaster_is_master_file(td, uap->path)) {
		*error = sys_access(td, (struct access_args *)uap);
		return (PRE_EXEC_END);
	}

	return (PRE_EXEC_CONT);
}

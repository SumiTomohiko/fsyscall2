#include <sys/param.h>
#include <sys/types.h>
#include <sys/libkern.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_stat_pre_execute(struct thread *td, struct fmaster_stat_args *uap, int *error)
{

	if (fmaster_is_master_file(td, uap->path)) {
		*error = sys_stat(td, (struct stat_args *)uap);
		return (0);
	}

	return (1);
}

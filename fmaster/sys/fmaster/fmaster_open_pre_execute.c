#include <sys/param.h>

#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_open_pre_execute(struct thread *td, struct fmaster_open_args *uap, int *error)
{
	return (1);
}

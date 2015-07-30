#include <sys/param.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_getdirentries(struct thread *td, struct fmaster_getdirentries_args *uap)
{
	enum fmaster_file_place place;
	int error, lfd;

	error = fmaster_get_vnode_info(td, uap->fd, &place, &lfd);
	if (error != 0)
		return (error);
	if (place != FFP_MASTER)
		return (EBADF);

	return (kern_getdirentries(td, lfd, uap->buf, uap->count, uap->basep));
}

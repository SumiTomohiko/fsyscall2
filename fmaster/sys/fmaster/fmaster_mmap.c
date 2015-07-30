#include <sys/param.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/sysproto.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
mmap_main(struct thread *td, struct fmaster_mmap_args *uap, int lfd)
{
	struct mmap_args a;

	memcpy(&a, uap, sizeof(a));
	a.fd = lfd;

	return (sys_mmap(td, &a));
}

int
sys_fmaster_mmap(struct thread *td, struct fmaster_mmap_args *uap)
{
	enum fmaster_file_place place;
	int error, lfd;

	if ((uap->flags & MAP_ANON) != 0)
		return (sys_mmap(td, (struct mmap_args *)uap));
	error = fmaster_get_vnode_info(td, uap->fd, &place, &lfd);
	if (error != 0)
		return (error);
	if (place == FFP_MASTER)
		return (mmap_main(td, uap, lfd));

	return (EBADF);
}

#include <sys/param.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/sysproto.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
mmap_main(struct thread *td, struct fmaster_mmap_args *uap)
{
	struct mmap_args a;

	memcpy(&a, uap, sizeof(a));
	if ((uap->flags & MAP_ANON) == 0)
		a.fd = fmaster_fds_of_thread(td)[uap->fd].fd_local;

	return (sys_mmap(td, &a));
}

int
sys_fmaster_mmap(struct thread *td, struct fmaster_mmap_args *uap)
{
	enum fmaster_fd_type type;
	int error;

	if ((uap->flags & MAP_ANON) != 0)
		return (mmap_main(td, uap));
	error = fmaster_type_of_fd(td, uap->fd, &type);
	if (error != 0)
		return (error);
	if (type == FD_MASTER)
		return (mmap_main(td, uap));

	return (EBADF);
}

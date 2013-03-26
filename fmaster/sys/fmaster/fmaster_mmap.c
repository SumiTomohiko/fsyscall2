#include <sys/param.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/sysproto.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_mmap(struct thread *td, struct fmaster_mmap_args *uap)
{
	int fd = uap->fd, *fds, flags = uap->flags;

	if (((flags & MAP_ANON) != 0) || (fmaster_type_of_fd(td, fd) == fft_master)) {
		struct mmap_args a;
		memcpy(&a, uap, sizeof(a));
		if ((flags & MAP_ANON) == 0) {
			fds = fmaster_fds_of_thread(td);
			a.fd = LOCAL_FD(fds[fd]);
		}
		return (sys_mmap(td, &a));
	}

	return (EBADF);
}

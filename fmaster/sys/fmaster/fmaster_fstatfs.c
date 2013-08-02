#include <sys/sysproto.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_fstatfs(struct thread *td, struct fmaster_fstatfs_args *uap)
{
	struct fstatfs_args a;
	int fd;

	fd = uap->fd;
	if (fmaster_type_of_fd(td, fd) != FD_MASTER)
		return (EBADF);

	a.fd = fmaster_fds_of_thread(td)[fd].fd_local;
	a.buf = uap->buf;
	return (sys_fstatfs(td, &a));
}

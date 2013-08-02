#include <sys/sysproto.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_getdirentries(struct thread *td, struct fmaster_getdirentries_args *uap)
{
	struct getdirentries_args a;
	int fd;

	fd = uap->fd;
	if (fmaster_type_of_fd(td, fd) != FD_MASTER)
		return (EBADF);

	a.fd = fmaster_fds_of_thread(td)[fd].fd_local;
	a.buf = uap->buf;
	a.count = uap->count;
	a.basep = uap->basep;
	return (sys_getdirentries(td, &a));
}

#include <sys/sysproto.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_ioctl(struct thread *td, struct fmaster_ioctl_args *uap)
{
	struct ioctl_args a;
	enum fmaster_fd_type type;
	int error, fd;

	fd = uap->fd;
	error = fmaster_type_of_fd(td, fd, &type);
	if (error != 0)
		return (error);
	if (type == FD_CLOSED)
		return (EBADF);
	if (type == FD_SLAVE)
		return (ENOTTY);
	a.fd = fmaster_fds_of_thread(td)[fd].fd_local;
	a.com = uap->com;
	a.data = uap->data;
	return (sys_ioctl(td, &a));
}

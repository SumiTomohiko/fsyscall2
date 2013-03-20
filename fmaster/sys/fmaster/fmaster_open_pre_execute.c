#include <sys/param.h>
#include <sys/libkern.h>
#include <sys/sysproto.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

static int
find_unused_fd(struct thread *td)
{
	int *fds, i;

	fds = fmaster_fds_of_thread(td);
	for (i = 0; (i < FD_NUM) && (fds[i] != 0); i++);

	return (i);
}

static int
open_master(struct thread *td, struct fmaster_open_args *uap)
{
	int error, fd, *fds, master_fd;

	error = sys_open(td, (struct open_args *)uap);
	if (error != 0)
		return (error);

	master_fd = td->td_retval[0];
	fd = find_unused_fd(td);
	if (fd == FD_NUM)
		return (EMFILE);
	fds = fmaster_fds_of_thread(td);
	fds[fd] = MASTER_FD2FD(master_fd);
	td->td_retval[0] = fd;

	return (error);
}

int
fmaster_open_pre_execute(struct thread *td, struct fmaster_open_args *uap, int *error)
{
	const char *dir = "/lib";

	if (strncmp(uap->path, dir, strlen(dir)) == 0) {
		*error = open_master(td, uap);
		return (0);
	}

	return (1);
}

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/syscallsubr.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

static int
fmaster_close_main(struct thread *td, struct fmaster_close_args *uap)
{
	enum fmaster_fd_type type_of_fd;
	int error, fd, lfd;

	fd = uap->fd;
	error = fmaster_type_of_fd(td, fd, &type_of_fd);
	if (error != 0)
		return (error);
	if (type_of_fd == FD_CLOSED)
		return (EBADF);
	lfd = fmaster_fds_of_thread(td)[fd].fd_local;
	if (type_of_fd == FD_MASTER) {
		error = kern_close(td, lfd);
		if (error != 0)
			return (error);
		error = fmaster_close_post_common(td, uap);
		if (error != 0)
			return (error);
		return (0);
	}

	error = fmaster_execute_close(td, lfd);
	if (error != 0)
		return (error);
	error = fmaster_close_post_common(td, uap);
	if (error != 0)
		return (error);
	return (0);
}

int
sys_fmaster_close(struct thread *td, struct fmaster_close_args *uap)
{
	struct timeval time_start;
	pid_t pid;
	int error;
	const char *name = "close";

	pid = td->td_proc->p_pid;
	log(LOG_DEBUG,
	    "fmaster[%d]: %s: started: fd=%d\n",
	    pid, name, uap->fd);
	microtime(&time_start);

	error = fmaster_close_main(td, uap);

	fmaster_log_syscall_end(td, name, &time_start, error);

	return (error);
}

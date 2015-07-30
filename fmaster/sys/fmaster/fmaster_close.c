#include <sys/param.h>
#include <sys/syscallsubr.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
fmaster_close_main(struct thread *td, struct fmaster_close_args *uap)
{
	int (*closef)(struct thread *, int);
	enum fmaster_file_place place;
	int error, fd, lfd, refcount;

	fd = uap->fd;
	error = fmaster_unref_fd(td, fd, &place, &lfd, &refcount);
	if (error != 0)
		return (error);

	if (refcount == 0) {
		closef = place == FFP_MASTER ? kern_close
					     : fmaster_execute_close;
		error = closef(td, lfd);
		if (error != 0)
			return (error);
	}

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

#include <sys/param.h>
#include <sys/proc.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
fmaster_dup_main(struct thread *td, int fd)
{
	int error, newfd;

	error = fmaster_dup(td, fd, &newfd);
	if (error != 0)
		return (error);
	td->td_retval[0] = newfd;

	return (0);
}

int
sys_fmaster_dup(struct thread *td, struct fmaster_dup_args *uap)
{
	struct timeval time_start;
	pid_t pid;
	int error, fd;

	pid = td->td_proc->p_pid;
	fd = uap->fd;
	log(LOG_DEBUG, "fmaster[%d]: dup: started: fd=%u\n", pid, fd);
	microtime(&time_start);

	error = fmaster_dup_main(td, fd);

	fmaster_log_syscall_end(td, "dup", &time_start, error);

	return (error);
}

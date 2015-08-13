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
	int error, fd;

	fd = uap->fd;
	fmaster_log(td, LOG_DEBUG, "dup: started: fd=%u", fd);
	microtime(&time_start);

	error = fmaster_dup_main(td, fd);

	fmaster_log_syscall_end(td, "dup", &time_start, error);

	return (error);
}

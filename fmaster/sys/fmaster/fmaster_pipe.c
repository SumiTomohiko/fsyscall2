#include <sys/param.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/libkern.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_pipe(struct thread *td, struct fmaster_pipe_args *uap)
{
	struct timeval time_start;
	pid_t pid;
	int error, fds[2], fildes[2];

	pid = td->td_proc->p_pid;
	log(LOG_DEBUG, "fmaster[%d]: pipe: started\n", pid);
	microtime(&time_start);

	error = kern_pipe(td, fildes);
	if (error != 0)
		return (error);

	error = fmaster_register_fd(td, FD_MASTER, fildes[0], &fds[0]);
	if (error != 0)
		return (error);
	error = fmaster_register_fd(td, FD_MASTER, fildes[1], &fds[1]);
	if (error != 0)
		return (error);
	td->td_retval[0] = fds[0];
	td->td_retval[1] = fds[1];

	fmaster_log_spent_time(td, "pipe: ended", &time_start);

	return (error);
}

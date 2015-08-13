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
#define	SYSCALL_NAME	"pipe"
	struct timeval time_start;
	int error, fds[2], fildes[2];

	fmaster_log(td, LOG_DEBUG, SYSCALL_NAME ": started");
	microtime(&time_start);

	error = kern_pipe(td, fildes);
	if (error != 0)
		return (error);

	error = fmaster_register_file(td, FFP_MASTER, fildes[0], &fds[0]);
	if (error != 0)
		return (error);
	error = fmaster_register_file(td, FFP_MASTER, fildes[1], &fds[1]);
	if (error != 0)
		return (error);
	td->td_retval[0] = fds[0];
	td->td_retval[1] = fds[1];

	fmaster_log_syscall_end(td, SYSCALL_NAME, &time_start, error);

	return (error);
#undef	SYSCALL_NAME
}

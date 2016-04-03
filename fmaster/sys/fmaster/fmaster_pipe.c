#include <sys/param.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/libkern.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

#define	R	0
#define	W	1

int
sys_fmaster_pipe(struct thread *td, struct fmaster_pipe_args *uap)
{
#define	SYSCALL_NAME	"pipe"
	struct timeval time_start;
	enum fmaster_file_place place;
	int error, fds[2], fildes[2], rfd, wfd;
	short type;
	const char *fmt = "pipe to %s (local %d to local %d)";
	char desc[VNODE_DESC_LEN], desc2[VNODE_DESC_LEN];

	fmaster_log(td, LOG_DEBUG, SYSCALL_NAME ": started");
	microtime(&time_start);

	error = kern_pipe(td, fildes);
	if (error != 0)
		return (error);

	rfd = fildes[R];
	wfd = fildes[W];
	snprintf(desc, sizeof(desc), fmt, "read", wfd, rfd);
	type = DTYPE_PIPE;
	place = FFP_MASTER;
	error = fmaster_register_file(td, type, place, rfd, &fds[0], desc);
	if (error != 0)
		return (error);
	snprintf(desc2, sizeof(desc2), fmt, "write", wfd, rfd);
	error = fmaster_register_file(td, type, place, wfd, &fds[1], desc2);
	if (error != 0)
		return (error);
	td->td_retval[0] = fds[0];
	td->td_retval[1] = fds[1];

	fmaster_log_syscall_end(td, SYSCALL_NAME, &time_start, error);

	return (error);
#undef	SYSCALL_NAME
}

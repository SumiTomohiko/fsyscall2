#include <sys/param.h>
#include <sys/errno.h>
#include <sys/syscallsubr.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
fmaster_dup2_main(struct thread *td, int from, int to)
{
	enum fmaster_file_place place;
	int error, lfd, refcount;

	/* The following code is needed to detect EBADF */
	error = fmaster_get_vnode_info(td, from, NULL, NULL);
	if (error != 0)
		return (error);

	if (from == to)
		return (0);

	error = fmaster_unref_fd(td, to, &place, &lfd, &refcount);
	if (error != EBADF) {
		if (error != 0)
			return (error);
		if (refcount == 0)
			switch (place) {
			case FFP_MASTER:
				error = kern_close(td, lfd);
				if (error != 0)
					return (error);
				break;
			case FFP_SLAVE:
				error = fmaster_execute_close(td, lfd);
				if (error != 0)
					return (error);
				break;
			default:
				return (EBADF);
			}
	}

	error = fmaster_dup2(td, from, to);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_dup2(struct thread *td, struct fmaster_dup2_args *uap)
{
	struct timeval time_start;
	int error, from, to;
	const char *name = "dup2";

	from = uap->from;
	to = uap->to;
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: from=%u, to=%u",
		    name, from, to);
	microtime(&time_start);

	error = fmaster_dup2_main(td, from, to);

	fmaster_log_syscall_end(td, name, &time_start, error);

	return (error);
}

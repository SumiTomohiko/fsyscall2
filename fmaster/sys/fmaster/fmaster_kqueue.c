#include <sys/param.h>
#include <sys/proc.h>
#include <sys/sysproto.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

static int
fmaster_kqueue_main(struct thread *td, struct fmaster_kqueue_args *uap)
{
	int error;

	error = sys_kqueue(td, NULL);
	if (error != 0)
		return (error);
	error = fmaster_kqueue_post_execute(td, uap);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_kqueue(struct thread *td, struct fmaster_kqueue_args *uap)
{
	struct timeval time_start;
	int error;

	fmaster_log(td, LOG_DEBUG, "kqueue: started");
	microtime(&time_start);

	error = fmaster_kqueue_main(td, uap);

	fmaster_log_syscall_end(td, "kqueue", &time_start, error);

	return (error);
}

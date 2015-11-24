#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
fmaster_thr_exit_main(struct thread *td, struct fmaster_thr_exit_args *uap)
{
	int error;

	error = fmaster_write_command(td, THR_EXIT_CALL);
	if (error != 0)
		return (error);
	error = fmaster_release_thread(td);
	if (error != 0)
		return (error);
	error = sys_thr_exit(td, (struct thr_exit_args *)uap);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_thr_exit(struct thread *td, struct fmaster_thr_exit_args *uap)
{
	struct timeval time_start;
	const char *sysname = "thr_exit";
	int error;

	fmaster_log(td, LOG_DEBUG, "%s: started", sysname);
	microtime(&time_start);

	error = fmaster_thr_exit_main(td, uap);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

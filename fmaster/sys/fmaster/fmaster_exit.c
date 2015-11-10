#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/proc.h>

#include <fsyscall/private/command.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
execute_call(struct thread *td, int rval)
{
	int error;

	error = fmaster_write_command(td, EXIT_CALL);
	if (error != 0)
		return (error);
	error = fmaster_write_int32(td, rval);
	if (error != 0)
		return (error);

	return (0);
}

static int
exit_main(struct thread *td, int rval)
{
	int error, error2;

	error = execute_call(td, rval);
	error2 = fmaster_release_thread(td);

	if (error != 0)
		return (error);
	if (error2 != 0)
		return (error2);

	return (0);
}

void
sys_fmaster_exit(struct thread *td, struct fmaster_exit_args *uap)
{
	int error, rval;

	rval = uap->rval;
	fmaster_log(td, LOG_DEBUG, "exit: started: rval=%d", rval);

	error = exit_main(td, rval);

	exit1(td, error == 0 ? rval : -1);
	/* NOTREACHED */
}

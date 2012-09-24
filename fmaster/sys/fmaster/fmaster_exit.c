#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/proc.h>

#include <fsyscall/private/command.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

void
sys_fmaster_exit(struct thread *td, struct fmaster_exit_args *uap)
{
	int error, rval;

	error = fmaster_write_command(td, CALL_EXIT);
	if (error != 0)
		exit1(td, -1);
	rval = uap->rval;
	error = fmaster_write_int32(td, rval);
	if (error != 0)
		exit1(td, -1);
	exit1(td, rval);
	/* NOTREACHED */
}

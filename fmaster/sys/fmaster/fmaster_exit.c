#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/proc.h>

#include <fsyscall/private/command.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

void
sys_fmaster_exit(struct thread *td, struct fmaster_exit_args *uap)
{
	int rval;

	fmaster_write_command_or_die(td, CALL_EXIT);
	rval = uap->rval;
	fmaster_write_int32_or_die(td, rval);
	exit1(td, rval);
	/* NOTREACHED */
}

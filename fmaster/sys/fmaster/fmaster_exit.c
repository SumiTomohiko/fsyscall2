#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/proc.h>

#include <fsyscall/fmaster.h>
#if 0
#include <fsyscall/syscall.h>
#endif
#include <sys/fmaster/fmaster_proto.h>

void
sys_fmaster_exit(struct thread *td, struct fmaster_exit_args *uap)
{
#if 0
	if (sys_fsyscall_write_syscall(td, SYSCALL_EXIT) != 0)
		return;
	int rval = uap->rval;
	if (sys_fsyscall_write_int(td, rval) != 0)
		return;
	exit1(td, rval);
#endif
	exit1(td, 0);
	/* NOTREACHED */
}

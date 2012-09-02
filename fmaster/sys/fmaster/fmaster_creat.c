#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/libkern.h>
#include <sys/proc.h>

#if 0
#include <fsyscall/syscall.h>
#endif
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_creat(struct thread *td, struct fmaster_creat_args *uap)
{
#if 0
	if (sys_fsyscall_write_syscall(td, SYSCALL_CREAT) < 0)
		return (-1);
	if (sys_fsyscall_write_str(td, uap->path) < 0)
		return (-1);
	if (sys_fsyscall_write_int(td, uap->mode) < 0)
		return (-1);
#endif
	return (0);
}

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/unistd.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

static int
do_fork(struct thread *td, pid_t slave_pid, const char *token,
	uint64_t token_size)
{
	struct thread *td2;
	struct proc *p2;
	struct fmaster_data *data2;
	int error;

	error = fork1(td, RFFDG | RFPROC | RFSTOPPED, 0, &p2, NULL, 0);
	if (error != 0)
		return (error);
	fmaster_log(td, LOG_DEBUG, "forked: the child is pid %d", p2->p_pid);

	td2 = FIRST_THREAD_IN_PROC(p2);
	error = fmaster_create_data2(td, slave_pid, td2->td_tid, token,
				     token_size, &data2);
	if (error != 0)
		return (error);

	p2->p_emuldata = data2;
	thread_lock(td2);
	TD_SET_CAN_RUN(td2);
	sched_add(td2, SRQ_BORING);
	thread_unlock(td2);

	return (0);
}

static int
fmaster_fork_main(struct thread *td, struct fmaster_fork_args *uap)
{
	uint64_t token_size;
	int error;
	char *token;

	error = fmaster_write_command_with_empty_payload(td, FORK_CALL);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_int32_with_token(td, FORK_RETURN, &token,
							&token_size);
	if (error != 0)
		return (error);
	error = do_fork(td, td->td_retval[0], token, token_size);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_fork(struct thread *td, struct fmaster_fork_args *uap)
{
#define	SYSCALL_NAME	"fork"
	struct timeval time_start;
	int error;

	fmaster_log(td, LOG_DEBUG, SYSCALL_NAME ": started");
	microtime(&time_start);

	error = fmaster_fork_main(td, uap);
	fmaster_freeall(td);

	fmaster_log_syscall_end(td, SYSCALL_NAME, &time_start, error);

	return (error);
#undef	SYSCALL_NAME
}

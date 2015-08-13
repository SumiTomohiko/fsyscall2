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
execute_call(struct thread *td, struct fmaster_fork_args *uap)
{
	payload_size_t payload_size;
	int error;

	error = fmaster_write_command(td, FORK_CALL);
	if (error != 0)
		return (error);
	payload_size = 0;
	error = fmaster_write_payload_size(td, payload_size);

	return (error);
}

MALLOC_DEFINE(M_TOKEN, "token", "buffer for token");

static int
do_fork(struct thread *td, const char *token, uint64_t token_size)
{
	struct thread *td2;
	struct proc *p2;
	struct fmaster_data *data2;
	int error;

	data2 = fmaster_create_data(td);
	if (data2 == NULL)
		return (ENOMEM);
	error = fmaster_copy_data(td, data2);
	if (error != 0)
		return (error);
	error = fmaster_set_token(data2, token, token_size);
	if (error != 0)
		return (error);

	error = fork1(td, RFFDG | RFPROC | RFSTOPPED, 0, &p2, NULL, 0);
	if (error != 0)
		return (error);
	fmaster_log(td, LOG_DEBUG, "forked: the child is pid %d", p2->p_pid);
	p2->p_emuldata = data2;
	td2 = FIRST_THREAD_IN_PROC(p2);
	thread_lock(td2);
	TD_SET_CAN_RUN(td2);
	sched_add(td2, SRQ_BORING);
	thread_unlock(td2);

	return (0);
}

static int
execute_return(struct thread *td, struct fmaster_fork_args *uap, char **ptoken, uint64_t *ptoken_size)
{
	payload_size_t payload_size;
	uint64_t token_size;
	command_t cmd;
	pid_t pid;
	int error, pid_size, token_size_size;
	char *token;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != FORK_RETURN)
		return (EPROTO);
	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_uint64(td, &token_size, &token_size_size);
	if (error != 0)
		return (error);
	*ptoken_size = token_size;
	token = (char *)malloc(token_size, M_TOKEN, M_WAITOK);
	if (token == NULL)
		return (ENOMEM);
	*ptoken = token;
	error = fmaster_read(td, fmaster_rfd_of_thread(td), token, token_size);
	if (error != 0)
		return (error);
	error = fmaster_read_int32(td, &pid, &pid_size);
	if (error != 0)
		return (error);
	td->td_retval[0] = pid;

	return (0);
}

static int
fmaster_fork_main(struct thread *td, struct fmaster_fork_args *uap)
{
	uint64_t token_size;
	int error;
	char *token = NULL;

	error = execute_call(td, uap);
	if (error != 0)
		return (error);
	error = execute_return(td, uap, &token, &token_size);
	if (error != 0)
		goto exit;
	error = do_fork(td, token, token_size);

exit:
	if (token != NULL)
		free(token, M_TOKEN);

	return (error);
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

	fmaster_log_syscall_end(td, SYSCALL_NAME, &time_start, error);

	return (error);
#undef	SYSCALL_NAME
}

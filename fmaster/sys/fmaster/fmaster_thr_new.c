#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
order_slave(struct thread *td, char **ptoken, uint64_t *ptoken_size)
{
	uint64_t token_size;
	int error;
	char *token;

	error = fmaster_write_command_with_empty_payload(td, THR_NEW_CALL);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_int32_with_token(td, THR_NEW_RETURN,
							&token, &token_size);
	if (error != 0)
		return (error);

	*ptoken = token;
	*ptoken_size = token_size;

	return (0);
}

static int
create_new_thread(struct thread *td, struct fmaster_thr_new_args *uap,
		  lwpid_t *tid)
{
	int error;

	error = sys_thr_new(td, (struct thr_new_args *)uap);
	if (error != 0)
		return (error);

	*tid = TAILQ_FIRST(&td->td_proc->p_threads)->td_tid;

	return (0);
}

static int
start_new_thread(struct thread *td, struct fmaster_thr_new_args *uap,
		 const char *token, uint64_t token_size)
{
	lwpid_t tid;
	int error, sock;

	fmaster_start_thread_creating(td);
	error = create_new_thread(td, uap, &tid);
	fmaster_end_thread_creating(td);
	if (error != 0)
		return (error);

	error = fmaster_add_thread(td, tid, sock, sock, token, token_size);
	if (error != 0)
		return (error);

	return (0);
}

static int
fmaster_thr_new_main(struct thread *td, struct fmaster_thr_new_args *uap)
{
	uint64_t token_size;
	int error;
	char *token;

	error = order_slave(td, &token, &token_size);
	if (error != 0)
		return (error);

	error = start_new_thread(td, uap, token, token_size);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_thr_new(struct thread *td, struct fmaster_thr_new_args *uap)
{
	struct timeval time_start;
	const char *sysname = "thr_new";
	int error;

	fmaster_log(td, LOG_DEBUG, "%s: started", sysname);
	microtime(&time_start);

	error = fmaster_thr_new_main(td, uap);
	fmaster_freeall(td);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

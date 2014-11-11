#include <sys/param.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/payload.h>
#include <sys/fmaster/fmaster_proto.h>

static int
execute_call(struct thread *td, struct fmaster_sigaction_args *uap)
{
	struct payload *payload;
	struct sigaction act;
	payload_size_t payload_size;
	int actcode, error, wfd;
	sig_t handler;
	const char *buf;

	error = copyin(uap->act, &act, sizeof(act));
	if (error != 0)
		return (error);
	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);
	error = fsyscall_payload_add_int32(payload, uap->sig);
	if (error != 0)
		goto exit;
	handler = (act.sa_flags & SA_SIGINFO) != 0 ? (sig_t)act.sa_sigaction
						   : (sig_t)act.sa_handler;
	if (handler == SIG_DFL) {
		actcode = SIGNAL_DEFAULT;
	}
	else if (handler == SIG_IGN) {
		actcode = SIGNAL_IGNORE;
	}
	else {
		actcode = SIGNAL_ACTIVE;
	}
	error = fsyscall_payload_add_uint8(payload, actcode);
	if (error != 0)
		return (error);
	error = fsyscall_payload_add_int32(payload, act.sa_flags);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_sigset(payload, &act.sa_mask);
	if (error != 0)
		goto exit;

	error = fmaster_write_command(td, CALL_SIGACTION);
	if (error != 0)
		return (error);
	payload_size = fsyscall_payload_get_size(payload);
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		return (error);
	wfd = fmaster_wfd_of_thread(td);
	buf = fsyscall_payload_get(payload);
	error = fmaster_write(td, wfd, buf, payload_size);
	if (error != 0)
		return (error);

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
fmaster_sigaction_main(struct thread *td, struct fmaster_sigaction_args *uap)
{
	int error;

	if (uap->act != NULL) {
		error = execute_call(td, uap);
		if (error != 0)
			return (error);
		error = fmaster_execute_return_generic32(td, RET_SIGACTION);
		if (error != 0)
			return (error);
	}

	error = sys_sigaction(td, (struct sigaction_args *)uap);

	return (error);
}

int
sys_fmaster_sigaction(struct thread *td, struct fmaster_sigaction_args *uap)
{
#define	SYSCALL_NAME	"sigaction"
	struct timeval time_start;
	int error;
	const char *fmt = "fmaster[%d]: " SYSCALL_NAME ": started: sig=%d";

	log(LOG_DEBUG, fmt, td->td_proc->p_pid, uap->sig);
	microtime(&time_start);

	error = fmaster_sigaction_main(td, uap);

	fmaster_log_syscall_end(td, SYSCALL_NAME, &time_start, error);

	return (error);
#undef	SYSCALL_NAME
}

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/payload.h>
#include <sys/fmaster/fmaster_proto.h>

static int
reuseaddr_write_call(struct thread *td, int s, int level, int optname,
		     int optval, int optlen)
{
	struct payload *payload;
	int error;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);
	error = fsyscall_payload_add_int(payload, s);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_int(payload, level);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_int(payload, optname);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_int(payload, optlen);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_int(payload, optval);
	if (error != 0)
		goto exit;

	error = fmaster_write_payloaded_command(td, CALL_SETSOCKOPT, payload);
	if (error != 0)
		goto exit;

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
reuseaddr_main(struct thread *td, int s, int level, int optname, void *val,
	       int valsize)
{
	int d, error, optval;

	d = fmaster_fds_of_thread(td)[s].fd_local;

	if (valsize != sizeof(int))
		return (EFAULT);
	error = copyin(val, &optval, valsize);
	if (error != 0)
		return (error);

	error = reuseaddr_write_call(td, d, level, optname, optval, valsize);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_generic32(td, RET_SETSOCKOPT);
	if (error != 0)
		return (error);

	return (0);
}

static int
fmaster_setsockopt_main(struct thread *td, int s, int level, int name, void *val, int valsize)
{

	switch (name) {
	case SO_REUSEADDR:
		return reuseaddr_main(td, s, level, name, val, valsize);
	default:
		break;
	}

	return (ENOPROTOOPT);
}

int
sys_fmaster_setsockopt(struct thread *td, struct fmaster_setsockopt_args *uap)
{
	struct timeval time_start;
	int error, level, name, s, valsize;
	const char *sysname = "setsockopt";
	void *val;

	s = uap->s;
	level = uap->level;
	name = uap->name;
	val = uap->val;
	valsize = uap->valsize;
	log(LOG_DEBUG,
	    "fmaster[%d]: %s: started: s=%d, level=0x%x, name=%d (%s), val=%p, "
	    "valsize=%d\n",
	    td->td_proc->p_pid, sysname, s, level, name,
	    fmaster_get_sockopt_name(name), val, valsize);

	error = fmaster_setsockopt_main(td, s, level, name, val, valsize);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

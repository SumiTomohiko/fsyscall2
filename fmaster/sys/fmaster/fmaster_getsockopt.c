#include <sys/param.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/payload.h>
#include <sys/fmaster/fmaster_proto.h>

static int
reuseaddr_write_call(struct thread *td, int s, int level, int name, socklen_t optlen)
{
	struct payload *payload;
	int error, d;

	d = fmaster_fds_of_thread(td)[s].fd_local;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);
	error = fsyscall_payload_add_int(payload, d);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_int(payload, level);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_int(payload, name);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_socklen(payload, optlen);
	if (error != 0)
		goto exit;

	error = fmaster_write_payloaded_command(td, GETSOCKOPT_CALL, payload);
	if (error != 0)
		goto exit;

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

struct reuseaddr_bonus {
	socklen_t optlen;
	int optval;
};

static int
reuseaddr_callback(struct thread *td, int retval,
		   payload_size_t *optional_payload_size, void *bonus)
{
	struct reuseaddr_bonus *p;
	int error, optlen_len, optval_len;

	p = (struct reuseaddr_bonus *)bonus;

	error = fmaster_read_socklen(td, &p->optlen, &optlen_len);
	if (error != 0)
		return (error);
	error = fmaster_read_int(td, &p->optval, &optval_len);
	if (error != 0)
		return (error);

	*optional_payload_size = optlen_len + optval_len;

	return (0);
}

static int
reuseaddr_read_return(struct thread *td, void *val, socklen_t *avalsize)
{
	struct reuseaddr_bonus bonus;
	int error;

	error = fmaster_execute_return_optional32(td, GETSOCKOPT_RETURN,
						  reuseaddr_callback, &bonus);
	if (error != 0)
		return (error);

	if (*avalsize < sizeof(int))
		return (ENOPROTOOPT);
	error = copyout(&bonus.optval, val, sizeof(bonus.optval));
	if (error != 0)
		return (error);
	*avalsize = bonus.optlen;

	return (0);
}

static int
reuseaddr_main(struct thread *td, int s, int level, int name, void *val, socklen_t *avalsize)
{
	int error;

	error = reuseaddr_write_call(td, s, level, name, *avalsize);
	if (error != 0)
		return (error);
	error = reuseaddr_read_return(td, val, avalsize);
	if (error != 0)
		return (error);

	return (0);
}

static int
fmaster_getsockopt_main(struct thread *td, int s, int level, int name, void *val, socklen_t *avalsize)
{

	if (level != SOL_SOCKET)
		return (ENOPROTOOPT);

	switch (name) {
	case SO_REUSEADDR:
		return (reuseaddr_main(td, s, level, name, val, avalsize));
	default:
		break;
	}

	return (ENOPROTOOPT);
}

int
sys_fmaster_getsockopt(struct thread *td, struct fmaster_getsockopt_args *uap)
{
	struct timeval time_start;
	socklen_t optlen;
	int error, level, name, s;
	const char *sysname = "getsockopt";
	void *avalsize, *val;

	s = uap->s;
	level = uap->level;
	name = uap->name;
	val = uap->val;
	avalsize = uap->avalsize;
	error = copyin(avalsize, &optlen, sizeof(optlen));
	if (error != 0)
		return (error);

	log(LOG_DEBUG,
	    "fmaster[%d]: %s: started: s=%d, level=0x%x, name=%d (%s), val=%p, "
	    "avalsize=%p (%d)\n",
	    td->td_proc->p_pid, sysname, s, level, name,
	    fmaster_get_sockopt_name(name), val, avalsize, optlen);

	error = fmaster_getsockopt_main(td, s, level, name, val, &optlen);
	if (error != 0)
		goto exit;

	error = copyout(&optlen, avalsize, sizeof(optlen));
	if (error != 0)
		goto exit;

exit:
	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

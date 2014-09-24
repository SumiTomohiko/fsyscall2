#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/payload.h>
#include <sys/fmaster/fmaster_proto.h>

static int
execute_call(struct thread *td, int s, socklen_t namelen)
{
	struct payload *payload;
	payload_size_t payload_size;
	int error, wfd;
	const char *buf;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);

	error = fsyscall_payload_add_int(payload, s);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_socklen(payload, namelen);
	if (error != 0)
		goto exit;

	error = fmaster_write_command(td, CALL_GETPEERNAME);
	if (error != 0)
		goto exit;
	payload_size = fsyscall_payload_get_size(payload);
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		goto exit;
	wfd = fmaster_wfd_of_thread(td);
	buf = fsyscall_payload_get(payload);
	error = fmaster_write(td, wfd, buf, payload_size);
	if (error != 0)
		goto exit;

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
execute_return(struct thread *td, struct sockaddr_storage *addr,
	       socklen_t *namelen)
{
	payload_size_t actual_payload_size, payload_size;
	command_t cmd;
	int addr_len, errnum, errnum_len, error, namelen_len, retval;
	int retval_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != RET_GETPEERNAME)
		return (EPROTO);

	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_int(td, &retval, &retval_len);
	if (error != 0)
		return (error);
	actual_payload_size = retval_len;
	if (retval != 0) {
		error = fmaster_read_int(td, &errnum, &errnum_len);
		if (error != 0)
			return (error);
		actual_payload_size += errnum_len;
		if (payload_size != actual_payload_size)
			return (EPROTO);
		return (errnum);
	}

	error = fmaster_read_socklen(td, namelen, &namelen_len);
	if (error != 0)
		return (error);
	actual_payload_size += retval_len;
	error = fmaster_read_sockaddr(td, addr, &addr_len);
	if (error != 0)
		return (error);
	actual_payload_size += addr_len;
	if (payload_size != actual_payload_size)
		return (EPROTO);
	td->td_retval[0] = retval;

	return (0);
}

static int
fmaster_getpeername_main(struct thread *td,
			 struct fmaster_getpeername_args *uap)
{
	struct sockaddr_storage addr;
	socklen_t actual_namelen, len, namelen;
	int error;

	error = copyin(uap->alen, &namelen, sizeof(namelen));
	if (error != 0)
		return (error);
	error = execute_call(td, uap->fdes, namelen);
	if (error != 0)
		return (error);
	error = execute_return(td, &addr, &actual_namelen);
	if (error != 0)
		return (error);
	len = MIN(MIN(sizeof(addr), namelen), actual_namelen);
	error = copyout(&addr, uap->asa, len);
	if (error != 0)
		return (error);
	error = copyout(&actual_namelen, uap->alen, sizeof(actual_namelen));
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_getpeername(struct thread *td, struct fmaster_getpeername_args *uap)
{
	struct timeval time_start;
	pid_t pid;
	int error;

	pid = td->td_proc->p_pid;
	log(LOG_DEBUG, "fmaster[%d]: getpeername: started: s=%d, name=%p, namelen=%p\n", pid, uap->fdes, uap->asa, uap->alen);
	microtime(&time_start);

	error = fmaster_getpeername_main(td, uap);
	log(LOG_DEBUG, "fmaster[%d]: getpeername: error=%d\n", pid, error);

	fmaster_log_spent_time(td, "getpeername: ended", &time_start);

	return (error);
}

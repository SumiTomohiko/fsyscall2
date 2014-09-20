#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <sys/un.h>

#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/payload.h>
#include <sys/fmaster/fmaster_proto.h>

static int
call_un(struct thread *td, int s, struct sockaddr *name, socklen_t namelen)
{
	struct payload *payload;
	payload_size_t payload_size;
	int error, wfd;
	const char *buf;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);

	error = fsyscall_payload_add_int32(payload, s);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_uint32(payload, namelen);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_sockaddr(payload, name);
	if (error != 0)
		goto exit;

	error = fmaster_write_command(td, CALL_CONNECT);
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

typedef int (*call_t)(struct thread *, int, struct sockaddr *, socklen_t);

static int
fmaster_connect_main(struct thread *td, struct fmaster_connect_args *uap)
{
	struct sockaddr_storage sockaddr;
	struct sockaddr *paddr;
	call_t call;
	int error;

	paddr = (struct sockaddr *)&sockaddr;
	error = copyin(uap->name, paddr, uap->namelen);
	if (error != 0)
		return (error);

	switch (paddr->sa_family) {
	case AF_LOCAL:
		call = call_un;
		break;
	default:
		return (EINVAL);
	}

	error = call(td, uap->s, paddr, uap->namelen);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_generic32(td, RET_CONNECT);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_connect(struct thread *td, struct fmaster_connect_args *uap)
{
	struct timeval time_start;
	pid_t pid;
	int error;

	pid = td->td_proc->p_pid;
	log(LOG_DEBUG, "fmaster[%d]: connect: started: s=%d, name=%p, namelen=%d\n", pid, uap->s, uap->name, uap->namelen);
	microtime(&time_start);

	error = fmaster_connect_main(td, uap);

	fmaster_log_spent_time(td, "connect: ended", &time_start);

	return (error);
}

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <fmaster/fmaster_proto.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>

MALLOC_DECLARE(M_POLLBUF);
MALLOC_DEFINE(M_POLLBUF, "pollbuf", "buffer for poll(2) in fmaster");

static int
do_execute(struct thread *td, struct pollfd *fds, int nfds, int timeout)
{
	payload_size_t payload_size, rest_size;
	int error, events_len, fd_len, i, nfds_len, timeout_len, wfd;
	char *p, payload[256];

	rest_size = sizeof(payload);
	p = payload;
	nfds_len = fsyscall_encode_int32(nfds, p, rest_size);
	if (nfds_len == -1)
		return (ENOMEM);
	rest_size -= nfds_len;
	p += nfds_len;

	for (i = 0; i < nfds; i++) {
		fd_len = fsyscall_encode_int32(fds[i].fd, p, rest_size);
		if (fd_len == -1)
			return (ENOMEM);
		rest_size -= fd_len;
		p += fd_len;

		events_len = fsyscall_encode_int16(fds[i].events, p, rest_size);
		if (events_len == -1)
			return (ENOMEM);
		rest_size -= events_len;
		p += events_len;
	}

	timeout_len = fsyscall_encode_int32(timeout, p, rest_size);
	if (timeout_len == -1)
		return (ENOMEM);
	rest_size -= timeout_len;

	error = fmaster_write_command(td, CALL_POLL);
	if (error != 0)
		return (error);
	payload_size = sizeof(payload) - rest_size;
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		return (error);
	wfd = fmaster_wfd_of_thread(td);
	error = fmaster_write(td, wfd, payload, payload_size);
	if (error != 0)
		return (error);

	return (0);
}

static int
do_return(struct thread *td, struct pollfd *fds, int nfds)
{
	payload_size_t actual_payload_size, payload_size;
	command_t cmd;
	int errnum, errnum_len, error, i, revents, revents_len, retval;
	int retval_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != RET_POLL)
		return (EPROTO);
	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	actual_payload_size = 0;
	error = fmaster_read_int32(td, &retval, &retval_len);
	if (error != 0)
		return (error);
	actual_payload_size += retval_len;
	td->td_retval[0] = retval;

	switch (retval) {
	case -1:
		error = fmaster_read_int32(td, &errnum, &errnum_len);
		if (error != 0)
			return (error);
		actual_payload_size += errnum_len;
		break;
	case 0:
		errnum = 0;
		break;
	default:
		for (i = 0; i < nfds; i++) {
			error = fmaster_read_int32(td, &revents, &revents_len);
			if (error != 0)
				return (error);
			actual_payload_size += revents_len;
			fds[i].revents = revents;
		}
		errnum = 0;
		break;
	}
	if (payload_size != actual_payload_size)
		return (EPROTO);

	return (errnum);
}

static int
do_poll(struct thread *td, struct fmaster_poll_args *uap, struct pollfd *fds)
{
	size_t len;
	int error, nfds;

	nfds = uap->nfds;
	len = sizeof(*fds) * nfds;
	error = copyin(uap->fds, fds, len);
	if (error != 0)
		return (error);
	error = do_execute(td, fds, nfds, uap->timeout);
	if (error != 0)
		return (error);
	error = do_return(td, fds, nfds);
	if (error != 0)
		return (error);
	error = copyout(fds, uap->fds, len);
	if (error != 0)
		return (error);

	return (0);
}

static int
fmaster_poll_main(struct thread *td, struct fmaster_poll_args *uap)
{
	nfds_t nfds;
	int error;
	struct pollfd *fds;

	nfds = uap->nfds;
	fds = (struct pollfd *)malloc(sizeof(*fds) * nfds, M_POLLBUF, M_WAITOK);
	if (fds == NULL)
		return (ENOMEM);
	error = do_poll(td, uap, fds);
	free(fds, M_POLLBUF);

	return (error);
}

int
sys_fmaster_poll(struct thread *td, struct fmaster_poll_args *uap)
{
	struct timeval time_start;
	int error;
#define	SYSCALL	"poll"

	log(LOG_DEBUG, "fmaster[%d]: " SYSCALL ": started: fds=%p, nfds=%d, timeout=%d\n", td->td_proc->p_pid, uap->fds, uap->nfds, uap->timeout);
	microtime(&time_start);

	error = fmaster_poll_main(td, uap);

	fmaster_log_spent_time(td, SYSCALL ": ended", &time_start);
#undef SYSCALL

	return (0);
}

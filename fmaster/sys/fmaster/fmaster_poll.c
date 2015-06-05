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
	int error, events_len, fd, fd_len, i, nfds_len, sfd, timeout_len, wfd;
	enum fmaster_fd_type type;
	char *p, payload[256];

	rest_size = sizeof(payload);
	p = payload;
	nfds_len = fsyscall_encode_int32(nfds, p, rest_size);
	if (nfds_len == -1)
		return (ENOMEM);
	rest_size -= nfds_len;
	p += nfds_len;

	for (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		error = fmaster_type_of_fd(td, fd, &type);
		if (error != 0)
			return (error);
		if (type != FD_SLAVE)
			return (EBADF);
		sfd = fmaster_fds_of_thread(td)[fd].fd_local;
		fd_len = fsyscall_encode_int32(sfd, p, rest_size);
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
	int error, nfds;

	nfds = uap->nfds;
	error = do_execute(td, fds, nfds, uap->timeout);
	if (error != 0)
		return (error);
	error = do_return(td, fds, nfds);
	if (error != 0)
		return (error);

	return (0);
}

static void
events_to_string(char *buf, size_t bufsize, short events)
{
	struct flag_definition defs[] = {
		DEFINE_FLAG(POLLIN),
		DEFINE_FLAG(POLLPRI),
		DEFINE_FLAG(POLLOUT),
		DEFINE_FLAG(POLLRDNORM),
		/*DEFINE_FLAG(POLLWRNORM),*/	/* same as POLLOUT */
		DEFINE_FLAG(POLLRDBAND),
		DEFINE_FLAG(POLLWRBAND),
		DEFINE_FLAG(POLLINIGNEOF),
		DEFINE_FLAG(POLLERR),
		DEFINE_FLAG(POLLHUP),
		DEFINE_FLAG(POLLNVAL)
	};

	fmaster_chain_flags(buf, bufsize, events, defs, array_sizeof(defs));
}

static int
fmaster_poll_main(struct thread *td, struct fmaster_poll_args *uap)
{
	struct malloc_type *mt;
	struct pollfd *fds, *p;
	size_t size;
	nfds_t i, nfds;
	pid_t pid;
	enum fmaster_fd_type fdtype;
	int error, fd, lfd;
	short events;
	const char *sfdtype;
	char sevents[256];

	nfds = uap->nfds;
	size = sizeof(*fds) * nfds;
	mt = M_POLLBUF;
	fds = (struct pollfd *)malloc(size, mt, M_WAITOK);
	if (fds == NULL)
		return (ENOMEM);
	error = copyin(uap->fds, fds, size);
	if (error != 0)
		goto exit;
	pid = td->td_proc->p_pid;
	for (i = 0; i < nfds; i++) {
		p = &fds[i];
		fd = p->fd;
		error = fmaster_type_of_fd(td, fd, &fdtype);
		if (error != 0)
			goto exit;
		sfdtype = fdtype == FD_MASTER ? "master"
					      : fdtype == FD_SLAVE ? "slave"
								   : "closed";
		lfd = fmaster_fds_of_thread(td)[fd].fd_local;
		events = p->events;
		events_to_string(sevents, sizeof(sevents), events);
		log(LOG_DEBUG,
		    "fmaster[%d]: poll: fds[%d]: fd=%d (%s: %d), events=%d (%s)"
		    ", revents=%d\n",
		    pid, i, fd, sfdtype, lfd, events, sevents, p->revents);
	}

	error = do_poll(td, uap, fds);
	if (error != 0)
		goto exit;

	error = copyout(fds, uap->fds, size);
	if (error != 0)
		goto exit;

exit:
	free(fds, mt);

	return (error);
}

int
sys_fmaster_poll(struct thread *td, struct fmaster_poll_args *uap)
{
	struct timeval time_start;
	int error;
	const char *name = "poll";

	log(LOG_DEBUG,
	    "fmaster[%d]: %s: started: fds=%p, nfds=%d, timeout=%d\n",
	    td->td_proc->p_pid, name, uap->fds, uap->nfds, uap->timeout);
	microtime(&time_start);

	error = fmaster_poll_main(td, uap);

	fmaster_log_syscall_end(td, name, &time_start, error);

	return (error);
}

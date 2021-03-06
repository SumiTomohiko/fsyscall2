#include <sys/param.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fmaster/fmaster_proto.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>

#define	IGNORED_FD	(-1)

#define	ENABLE_DEBUG	0

/*******************************************************************************
 * shared code
 */

static const char *sysname = "poll";

#define	EVENTS_FOR_EVFILT_READ	(POLLIN | POLLRDNORM)
#define	EVENTS_FOR_EVFILT_WRITE	(POLLOUT | POLLWRNORM)

static int
count_kevents(struct pollfd *fds, nfds_t nfds)
{
	nfds_t i;
	int events, nkev;

	nkev = 0;
	for (i = 0; i < nfds; i++) {
		events = fds[i].events;
		if ((events & EVENTS_FOR_EVFILT_READ) != 0)
			nkev++;
		if ((events & EVENTS_FOR_EVFILT_WRITE) != 0)
			nkev++;
		/* TODO: The other events are ignored */
	}

	return (nkev);
}

static int
convert_pollfd_to_kevent(struct kevent *kev, struct pollfd *fds, nfds_t nfds)
{
	struct kevent *pkev;
	struct pollfd *pfd;
	nfds_t i;
	int events, fd;

	pkev = kev;
	for (i = 0; i < nfds; i++) {
		pfd = &fds[i];
		fd = pfd->fd;
		events = pfd->events;
		if ((events & EVENTS_FOR_EVFILT_READ) != 0) {
			EV_SET(pkev, fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0,
			       NULL);
			pkev++;
		}
		if ((events & EVENTS_FOR_EVFILT_WRITE) != 0) {
			EV_SET(pkev, fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0,
			       NULL);
			pkev++;
		}

	}

	return (0);
}

static int
convert_kevent_to_pollfd(struct pollfd *fds, nfds_t nfds, struct kevent *kev,
			 int nkev)
{
	struct kevent *pkev;
	struct pollfd *pfd;
	nfds_t j;
	int fd, i;

	for (i = 0; i < nkev; i++) {
		pkev = &kev[i];
		fd = pkev->ident;
		for (j = 0; (j < nfds) && (fds[j].fd != fd); j++)
			;
		if (j == nfds)
			return (EINVAL);
		pfd = &fds[j];
		switch (pkev->filter) {
		case EVFILT_READ:
			pfd->revents |= (pfd->events & EVENTS_FOR_EVFILT_READ);
			break;
		case EVFILT_WRITE:
			pfd->revents |= (pfd->events & EVENTS_FOR_EVFILT_WRITE);
			break;
		default:
			/* TODO */
			break;
		}
	}

	return (0);
}

static int
kevent_poll(struct thread *td, struct pollfd *fds, nfds_t nfds, int timeout)
{
	struct malloc_type *mt;
	struct kevent *changelist, *eventlist;
	struct timespec *pts, ts;
	size_t size;
	nfds_t i;
	int error, n, neventlist, nkev;

	nkev = count_kevents(fds, nfds);
	size = sizeof(changelist[0]) * nkev;
	mt = M_TEMP;
	changelist = (struct kevent *)malloc(size, mt, M_WAITOK);
	if (changelist == NULL)
		return (ENOMEM);
	error = convert_pollfd_to_kevent(changelist, fds, nfds);
	if (error != 0)
		goto exit1;
	eventlist = (struct kevent *)malloc(size, mt, M_WAITOK);
	if (eventlist == NULL) {
		error = ENOMEM;
		goto exit1;
	}
	if (timeout != INFTIM) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		pts = &ts;
	}
	else
		pts = NULL;

	error = fmaster_do_kevent(td, changelist, nkev, eventlist, &neventlist,
				  pts);
	if (error != 0)
		goto exit2;

	error = convert_kevent_to_pollfd(fds, nfds, eventlist, neventlist);
	if (error != 0)
		goto exit2;

exit2:
	free(eventlist, mt);
exit1:
	free(changelist, mt);

	if (error == 0) {
		n = 0;
		for (i = 0; i < nfds; i++)
			n += fds[i].revents != 0 ? 1 : 0;
		td->td_retval[0] = n;
	}

	return (error);
}

static int
vfd_to_lfd(struct thread *td, struct pollfd *fds, nfds_t nfds)
{
	struct pollfd *pfd;
	nfds_t i;
	int error, lfd;

	for (i = 0; i < nfds; i++) {
		pfd = &fds[i];
		error = fmaster_get_vnode_info(td, pfd->fd, NULL, &lfd);
		if (error != 0)
			return (error);
		pfd->fd = lfd;
	}

	return (0);
}

static int
read_result(struct thread *td, command_t expected_cmd, struct pollfd *fds,
	    nfds_t nfds)
{
	payload_size_t actual_payload_size, payload_size;
	command_t cmd;
	nfds_t i;
	int errnum, errnum_len, error, revents, revents_len, retval, retval_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != expected_cmd)
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
write_fds_command(struct thread *td, command_t cmd, struct pollfd *fds,
		  nfds_t nfds, int timeout)
{
	payload_size_t payload_size, rest_size;
	nfds_t i;
	int error, events_len, fd, fd_len, nfds_len, timeout_len, wfd;
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
		fd_len = fsyscall_encode_int32(fd, p, rest_size);
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

	error = fmaster_write_command(td, cmd);
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
pickup_local_fds(struct thread *td, enum fmaster_file_place where,
		 const struct pollfd *srcfds, nfds_t nsrcfds,
		 struct pollfd *destfds, nfds_t *ndestfds)
{
	const struct pollfd *pfd;
	struct pollfd *p;
	nfds_t i, max, n;
	enum fmaster_file_place place;
	int error, fd, lfd;

	max = *ndestfds;

	for (i = 0, n = 0; (i < nsrcfds) && (n < max); i++) {
		pfd = &srcfds[i];
		fd = pfd->fd;
		if (fd == IGNORED_FD)
			continue;
		error = fmaster_get_vnode_info(td, fd, &place, &lfd);
		if (error != 0)
			return (error);
		if (place != where)
			continue;
		p = &destfds[n];
		p->fd = lfd;
		p->events = pfd->events;
		p->revents = pfd->revents;
		n++;
	}

	*ndestfds = n;

	return (0);
}

static int
merge_results(struct thread *td, struct pollfd *fds, nfds_t nfds,
	      const struct pollfd *slavefds, nfds_t nslavefds,
	      const struct pollfd *masterfds, nfds_t nmasterfds)
{
	const struct pollfd *p;
	struct pollfd *pfd;
	nfds_t i, masterfdspos, slavefdspos;
	enum fmaster_file_place place;
	int error, fd;

	for (i = masterfdspos = slavefdspos = 0; i < nfds; i++) {
		pfd = &fds[i];
		fd = pfd->fd;
		if (fd == -1)
			continue;
		error = fmaster_get_vnode_info(td, fd, &place, NULL);
		if (error != 0)
			return (error);
		switch (place) {
		case FFP_MASTER:
			p = &masterfds[masterfdspos];
			masterfdspos++;
			break;
		case FFP_SLAVE:
			p = &slavefds[slavefdspos];
			slavefdspos++;
			break;
		case FFP_PENDING_SOCKET:
			p = NULL;
			break;
		default:
			return (EBADF);
		}
		pfd->revents = p != NULL ? p->revents : 0;
	}

	return (0);
}

/*******************************************************************************
 * code for slave
 */

static int
do_execute(struct thread *td, struct pollfd *fds, nfds_t nfds, int timeout)
{
	int error;

	error = write_fds_command(td, POLL_CALL, fds, nfds, timeout);
	if (error != 0)
		return (error);

	return (0);
}

static int
do_return(struct thread *td, struct pollfd *fds, nfds_t nfds)
{
	int error;

	error = read_result(td, POLL_RETURN, fds, nfds);
	if (error != 0)
		return (error);

	return (0);
}

static int
slave_poll(struct thread *td, struct pollfd *fds, nfds_t nfds, int timeout)
{
	struct malloc_type *mt;
	struct pollfd *p;
	nfds_t n;
	int error;

	n = nfds;

	mt = M_TEMP;
	p = (struct pollfd *)malloc(sizeof(*p) * n, mt, M_WAITOK);
	if (p == NULL)
		return (ENOMEM);
	error = pickup_local_fds(td, FFP_SLAVE, fds, nfds, p, &n);
	if (error != 0)
		goto exit;

	error = do_execute(td, p, n, timeout);
	if (error != 0)
		goto exit;
	error = do_return(td, p, n);
	if (error != 0)
		goto exit;
	error = merge_results(td, fds, nfds, p, n, NULL, 0);
	if (error != 0)
		goto exit;

	error = 0;
exit:
	free(p, M_TEMP);

	return (error);
}

/*******************************************************************************
 * code for master
 */

static int
master_poll(struct thread *td, struct pollfd *fds, nfds_t nfds, int timeout)
{
	struct malloc_type *mt;
	struct pollfd *p;
	int error, n;

	n = nfds;

	mt = M_TEMP;
	p = (struct pollfd *)malloc(sizeof(*p) * n, mt, M_WAITOK);
	if (p == NULL)
		return (ENOMEM);
	error = pickup_local_fds(td, FFP_MASTER, fds, nfds, p, &n);
	if (error != 0)
		goto exit;

	error = kevent_poll(td, p, n, timeout);
	if (error != 0)
		goto exit;

	error = merge_results(td, fds, nfds, NULL, 0, p, n);
	if (error != 0)
		goto exit;

	error = 0;
exit:
	free(p, mt);

	return (error);
}

/*******************************************************************************
 * code for both of master and slave
 */

#if ENABLE_DEBUG
static void
dump_fds(struct thread *td, const char *name, struct pollfd *fds, nfds_t nfds)
{
	struct pollfd *pfd;
	nfds_t i;
	int fd;

	for (i = 0; i < nfds; i++) {
		pfd = &fds[i];
		fd = pfd->fd;
		fmaster_log(td, LOG_DEBUG,
			    "%s: %s: fds[%d]: fd=%d, events=%d, revents=%d",
			    sysname, name, i, fd, pfd->events, pfd->revents);
	}
}
#endif

static int
master_slave_poll(struct thread *td, struct pollfd *fds, nfds_t nfds,
		  int timeout)
{
	struct malloc_type *mt;
	struct pollfd *masterfds, *mhubfd, *slavefds;
	nfds_t nmasterfds, nslavefds;
	size_t masterfdssize, slavefdssize;
	int error, master_retval, mhub_retval, slave_retval;

	nslavefds = nfds;
	mt = M_TEMP;
	slavefdssize = sizeof(slavefds[0]) * nslavefds;
	slavefds = (struct pollfd *)malloc(slavefdssize, mt, M_WAITOK);
	if (slavefds == NULL)
		return (ENOMEM);
	error = pickup_local_fds(td, FFP_SLAVE, fds, nfds, slavefds,
				 &nslavefds);
	if (error != 0)
		goto exit1;

	error = write_fds_command(td, POLL_START, slavefds, nslavefds, INFTIM);
	if (error != 0)
		goto exit1;

	nmasterfds = nfds - nslavefds;	/* does not include the mhub socket */
	masterfdssize = sizeof(masterfds[0]) * (nmasterfds + 1);
	masterfds = (struct pollfd *)malloc(masterfdssize, mt, M_WAITOK);
	if (masterfds == NULL) {
		error = ENOMEM;
		goto exit1;
	}
	error = pickup_local_fds(td, FFP_MASTER, fds, nfds, masterfds,
				 &nmasterfds);
	if (error != 0)
		goto exit2;
	mhubfd = &masterfds[nmasterfds];
	mhubfd->fd = fmaster_rfd_of_thread(td);
	mhubfd->events = POLLIN;
	mhubfd->revents = 0;

	error = kevent_poll(td, masterfds, nmasterfds + 1, timeout);
	if (error != 0)
		goto exit2;
	mhub_retval = (mhubfd->revents & POLLIN) != 0 ? 1 : 0;
	master_retval = td->td_retval[0] - mhub_retval;

	error = fmaster_write_command(td, POLL_END);
	if (error != 0)
		goto exit2;
	error = read_result(td, POLL_ENDED, slavefds, nslavefds);
	if (error != 0)
		goto exit2;
	slave_retval = td->td_retval[0];

#if ENABLE_DEBUG
	dump_fds(td, "master", masterfds, nmasterfds + 1);
	dump_fds(td, "slave", slavefds, nslavefds);
#endif
	error = merge_results(td, fds, nfds, slavefds, nslavefds, masterfds,
			      nmasterfds);
	if (error != 0)
		goto exit2;
#if ENABLE_DEBUG
	fmaster_log(td, LOG_DEBUG,
		    "%s: master_retval=%d", sysname, master_retval);
	fmaster_log(td, LOG_DEBUG,
		    "%s: slave_retval=%d", sysname, slave_retval);
#endif
	td->td_retval[0] = master_retval + slave_retval;

exit2:
	free(masterfds, mt);
exit1:
	free(slavefds, mt);

	return (error);
}

/*******************************************************************************
 * system call entry
 */

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
log_args(struct thread *td, const char *tag, struct pollfd *fds, nfds_t nfds)
{
	struct pollfd *pfd;
	nfds_t i;
	pid_t pid;
	enum fmaster_file_place place;
	int error, fd, lfd;
	short events, revents;
	const char *filedesc;
	char desc[256], sevents[256], srevents[256];

	pid = td->td_proc->p_pid;
	for (i = 0; i < nfds; i++) {
		pfd = &fds[i];
		fd = pfd->fd;
		if (fd != IGNORED_FD) {
			error = fmaster_get_vnode_info2(td, fd, &place, &lfd,
							&filedesc);
			if (error == 0)
				snprintf(desc, sizeof(desc),
					 "%s: %d, %s",
					 fmaster_str_of_place(place), lfd,
					 filedesc);
			else
				strcpy(desc, "invalid");
		}
		else
			strcpy(desc, "ignored");

		events = pfd->events;
		events_to_string(sevents, sizeof(sevents), events);
		revents = pfd->revents;
		events_to_string(srevents, sizeof(srevents), revents);
		fmaster_log(td, LOG_DEBUG,
			    "%s: %s: fds[%d]: fd=%d (%s), events=0x%x (%s), rev"
			    "ents=0x%x (%s)",
			    sysname, tag, i, fd, desc, events, sevents, revents,
			    srevents);
	}

	return (0);
}

enum fmaster_side {
	SIDE_NOTHING = 0,
	SIDE_MASTER = 0x01,
	SIDE_SLAVE = 0x02,
	SIDE_BOTH = SIDE_MASTER | SIDE_SLAVE
};

static int
detect_side(struct thread *td, struct pollfd *fds, nfds_t nfds,
	    enum fmaster_side *side)
{
	nfds_t i;
	enum fmaster_file_place place;
	int error, fd;

	*side = SIDE_NOTHING;
	for (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		if (fd == IGNORED_FD)
			continue;
		error = fmaster_get_vnode_info(td, fd, &place, NULL);
		if (error != 0)
			return (error);
		switch (place) {
		case FFP_MASTER:
			*side |= SIDE_MASTER;
			break;
		case FFP_SLAVE:
			*side |= SIDE_SLAVE;
			break;
		case FFP_PENDING_SOCKET:
			break;
		default:
			return (EBADF);
		}
		if (*side == SIDE_BOTH)
			break;
	}

	return (0);
}

static int
fmaster_poll_main(struct thread *td, struct fmaster_poll_args *uap)
{
	struct malloc_type *mt;
	struct pollfd *dest, *fds, *src;
	size_t size;
	nfds_t i, nfds;
	enum fmaster_side side;
	int error, timeout;

	nfds = uap->nfds;
	size = sizeof(*fds) * nfds;
	mt = M_TEMP;
	fds = (struct pollfd *)malloc(size, mt, M_WAITOK);
	if (fds == NULL)
		return (ENOMEM);
	error = copyin(uap->fds, fds, size);
	if (error != 0)
		goto exit;
	error = log_args(td, "input", fds, nfds);
	if (error != 0)
		goto exit;

	error = detect_side(td, fds, nfds, &side);
	if (error != 0)
		goto exit;
	timeout = uap->timeout;
	switch (side) {
	case SIDE_NOTHING:
		td->td_retval[0] = 0;
		break;
	case SIDE_MASTER:
		error = master_poll(td, fds, nfds, timeout);
		break;
	case SIDE_SLAVE:
		error = slave_poll(td, fds, nfds, timeout);
		break;
	case SIDE_BOTH:
		error = master_slave_poll(td, fds, nfds, timeout);
		break;
	default:
		error = EBADF;
		break;
	}
	if (error != 0)
		goto exit;
	error = log_args(td, "output", fds, nfds);
	if (error != 0)
		goto exit;

	dest = uap->fds;
	src = fds;
	for (i = 0; i < nfds; i++) {
		error = copyout(&src->revents, &dest->revents,
				sizeof(src->revents));
		if (error != 0)
			goto exit;
		dest++;
		src++;
	}

exit:
	free(fds, mt);

	return (error);
}

int
sys_fmaster_poll(struct thread *td, struct fmaster_poll_args *uap)
{
	struct timeval time_start;
	int error;

	fmaster_log(td, LOG_DEBUG,
		    "%s: started: fds=%p, nfds=%d, timeout=%d",
		    sysname, uap->fds, uap->nfds, uap->timeout);
	microtime(&time_start);

	error = fmaster_poll_main(td, uap);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

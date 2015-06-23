#include <sys/param.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/selinfo.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <fmaster/fmaster_proto.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>

/*******************************************************************************
 * shared code
 */

static int
read_result(struct thread *td, command_t expected_cmd, struct pollfd *fds,
	    int nfds)
{
	payload_size_t actual_payload_size, payload_size;
	command_t cmd;
	int errnum, errnum_len, error, i, revents, revents_len, retval;
	int retval_len;

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
		  int nfds, int timeout)
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

/*******************************************************************************
 * code for slave
 */

static int
do_execute(struct thread *td, struct pollfd *fds, int nfds, int timeout)
{
	int error;

	error = write_fds_command(td, POLL_CALL, fds, nfds, timeout);
	if (error != 0)
		return (error);

	return (0);
}

static int
do_return(struct thread *td, struct pollfd *fds, int nfds)
{
	int error;

	error = read_result(td, POLL_RETURN, fds, nfds);
	if (error != 0)
		return (error);

	return (0);
}

static int
slave_poll(struct thread *td, struct fmaster_poll_args *uap, struct pollfd *fds)
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

/*******************************************************************************
 * code for master
 */

static MALLOC_DEFINE(M_SELECT, "fselect", "select() buffer for fmaster");

/*
 * One seltd per-thread allocated on demand as needed.
 *
 *	t - protected by st_mtx
 * 	k - Only accessed by curthread or read-only
 */
struct seltd {
	STAILQ_HEAD(, selfd)	st_selq;	/* (k) List of selfds. */
	struct selfd		*st_free1;	/* (k) free fd for read set. */
	struct selfd		*st_free2;	/* (k) free fd for write set. */
	struct mtx		st_mtx;		/* Protects struct seltd */
	struct cv		st_wait;	/* (t) Wait channel. */
	int			st_flags;	/* (t) SELTD_ flags. */
};

#define	SELTD_PENDING	0x0001			/* We have pending events. */
#define	SELTD_RESCAN	0x0002			/* Doing a rescan. */

/*
 * One selfd allocated per-thread per-file-descriptor.
 *	f - protected by sf_mtx
 */
struct selfd {
	STAILQ_ENTRY(selfd)	sf_link;	/* (k) fds owned by this td. */
	TAILQ_ENTRY(selfd)	sf_threads;	/* (f) fds on this selinfo. */
	struct selinfo		*sf_si;		/* (f) selinfo when linked. */
	struct mtx		*sf_mtx;	/* Pointer to selinfo mtx. */
	struct seltd		*sf_td;		/* (k) owning seltd. */
	void			*sf_cookie;	/* (k) fd or pollfd. */
};

static uma_zone_t selfd_zone;

static void
seltdinit(struct thread *td)
{
	struct seltd *stp;

	if ((stp = td->td_sel) != NULL)
		goto out;
	td->td_sel = stp = malloc(sizeof(*stp), M_SELECT, M_WAITOK|M_ZERO);
	mtx_init(&stp->st_mtx, "sellck", NULL, MTX_DEF);
	cv_init(&stp->st_wait, "select");
out:
	stp->st_flags = 0;
	STAILQ_INIT(&stp->st_selq);
}

/*
 * Preallocate two selfds associated with 'cookie'.  Some fo_poll routines
 * have two select sets, one for read and another for write.
 */
static void
selfdalloc(struct thread *td, void *cookie)
{
	struct seltd *stp;

	stp = td->td_sel;
	if (stp->st_free1 == NULL)
		stp->st_free1 = uma_zalloc(selfd_zone, M_WAITOK|M_ZERO);
	stp->st_free1->sf_td = stp;
	stp->st_free1->sf_cookie = cookie;
	if (stp->st_free2 == NULL)
		stp->st_free2 = uma_zalloc(selfd_zone, M_WAITOK|M_ZERO);
	stp->st_free2->sf_td = stp;
	stp->st_free2->sf_cookie = cookie;
}

static int
pollscan(struct thread *td, struct pollfd *fds, u_int nfd)
{
	struct filedesc *fdp = td->td_proc->p_fd;
	int i;
	struct file *fp;
	int n = 0;

	FILEDESC_SLOCK(fdp);
	for (i = 0; i < nfd; i++, fds++) {
		if (fds->fd >= fdp->fd_nfiles) {
			fds->revents = POLLNVAL;
			n++;
		} else if (fds->fd < 0) {
			fds->revents = 0;
		} else {
			fp = fdp->fd_ofiles[fds->fd];
#ifdef CAPABILITIES
			if ((fp == NULL)
			    || (cap_funwrap(fp, CAP_POLL_EVENT, &fp) != 0)) {
#else
			if (fp == NULL) {
#endif
				fds->revents = POLLNVAL;
				n++;
			} else {
				/*
				 * Note: backend also returns POLLHUP and
				 * POLLERR if appropriate.
				 */
				selfdalloc(td, fds);
				fds->revents = fo_poll(fp, fds->events,
				    td->td_ucred, td);
				/*
				 * POSIX requires POLLOUT to be never
				 * set simultaneously with POLLHUP.
				 */
				if ((fds->revents & POLLHUP) != 0)
					fds->revents &= ~POLLOUT;

				if (fds->revents != 0)
					n++;
			}
		}
	}
	FILEDESC_SUNLOCK(fdp);
	td->td_retval[0] = n;
	return (0);
}

static int
seltdwait(struct thread *td, int timo)
{
	struct seltd *stp;
	int error;

	stp = td->td_sel;
	/*
	 * An event of interest may occur while we do not hold the seltd
	 * locked so check the pending flag before we sleep.
	 */
	mtx_lock(&stp->st_mtx);
	/*
	 * Any further calls to selrecord will be a rescan.
	 */
	stp->st_flags |= SELTD_RESCAN;
	if (stp->st_flags & SELTD_PENDING) {
		mtx_unlock(&stp->st_mtx);
		return (0);
	}
	if (timo > 0)
		error = cv_timedwait_sig(&stp->st_wait, &stp->st_mtx, timo);
	else
		error = cv_wait_sig(&stp->st_wait, &stp->st_mtx);
	mtx_unlock(&stp->st_mtx);

	return (error);
}

static void
selfdfree(struct seltd *stp, struct selfd *sfp)
{
	STAILQ_REMOVE(&stp->st_selq, sfp, selfd, sf_link);
	mtx_lock(sfp->sf_mtx);
	if (sfp->sf_si)
		TAILQ_REMOVE(&sfp->sf_si->si_tdlist, sfp, sf_threads);
	mtx_unlock(sfp->sf_mtx);
	uma_zfree(selfd_zone, sfp);
}

static int
pollrescan(struct thread *td)
{
	struct seltd *stp;
	struct selfd *sfp;
	struct selfd *sfn;
	struct selinfo *si;
	struct filedesc *fdp;
	struct file *fp;
	struct pollfd *fd;
	int n;

	n = 0;
	fdp = td->td_proc->p_fd;
	stp = td->td_sel;
	FILEDESC_SLOCK(fdp);
	STAILQ_FOREACH_SAFE(sfp, &stp->st_selq, sf_link, sfn) {
		fd = (struct pollfd *)sfp->sf_cookie;
		si = sfp->sf_si;
		selfdfree(stp, sfp);
		/* If the selinfo wasn't cleared the event didn't fire. */
		if (si != NULL)
			continue;
		fp = fdp->fd_ofiles[fd->fd];
#ifdef CAPABILITIES
		if ((fp == NULL)
		    || (cap_funwrap(fp, CAP_POLL_EVENT, &fp) != 0)) {
#else
		if (fp == NULL) {
#endif
			fd->revents = POLLNVAL;
			n++;
			continue;
		}

		/*
		 * Note: backend also returns POLLHUP and
		 * POLLERR if appropriate.
		 */
		fd->revents = fo_poll(fp, fd->events, td->td_ucred, td);
		if (fd->revents != 0)
			n++;
	}
	FILEDESC_SUNLOCK(fdp);
	stp->st_flags = 0;
	td->td_retval[0] = n;
	return (0);
}

/*
 * Remove the references to the thread from all of the objects we were
 * polling.
 */
static void
seltdclear(struct thread *td)
{
	struct seltd *stp;
	struct selfd *sfp;
	struct selfd *sfn;

	stp = td->td_sel;
	STAILQ_FOREACH_SAFE(sfp, &stp->st_selq, sf_link, sfn)
		selfdfree(stp, sfp);
	stp->st_flags = 0;
}

static int
sys_poll(struct thread *td, struct pollfd *bits, nfds_t nfds, int timeout)
{
	struct timeval atv, rtv, ttv;
	int error, timo;

	if (nfds > maxfilesperproc && nfds > FD_SETSIZE)
		return (EINVAL);
	if (timeout != INFTIM) {
		atv.tv_sec = timeout / 1000;
		atv.tv_usec = (timeout % 1000) * 1000;
		if (itimerfix(&atv)) {
			error = EINVAL;
			goto done;
		}
		getmicrouptime(&rtv);
		timevaladd(&atv, &rtv);
	} else {
		atv.tv_sec = 0;
		atv.tv_usec = 0;
	}
	timo = 0;
	seltdinit(td);
	/* Iterate until the timeout expires or descriptors become ready. */
	for (;;) {
		error = pollscan(td, bits, nfds);
		if (error || td->td_retval[0] != 0)
			break;
		if (atv.tv_sec || atv.tv_usec) {
			getmicrouptime(&rtv);
			if (timevalcmp(&rtv, &atv, >=))
				break;
			ttv = atv;
			timevalsub(&ttv, &rtv);
			timo = ttv.tv_sec > 24 * 60 * 60 ?
			    24 * 60 * 60 * hz : tvtohz(&ttv);
		}
		error = seltdwait(td, timo);
		if (error)
			break;
		error = pollrescan(td);
		if (error || td->td_retval[0] != 0)
			break;
	}
	seltdclear(td);

done:
	/* poll is not restarted after signals... */
	if (error == ERESTART)
		error = EINTR;
	if (error == EWOULDBLOCK)
		error = 0;

	return (error);
}

static int
vfd_to_lfd(struct thread *td, struct pollfd *fds, nfds_t nfds)
{
	struct pollfd *pfd;
	nfds_t i;

	for (i = 0; i < nfds; i++) {
		pfd = &fds[i];
		pfd->fd = fmaster_fds_of_thread(td)[pfd->fd].fd_local;
	}

	return (0);
}

static int
master_poll(struct thread *td, struct pollfd *fds, nfds_t nfds, int timeout)
{
	nfds_t i;
	int error, n;

	error = vfd_to_lfd(td, fds, nfds);
	if (error != 0)
		return (error);

	error = sys_poll(td, fds, nfds, timeout);
	if (error != 0)
		return (error);

	n = 0;
	for (i = 0; i < nfds; i++)
		n += fds[i].revents != 0 ? 1 : 0;
	td->td_retval[0] = n;
	/*
	 * File descriptors are still local. Because what will be copyouted are
	 * only revents.
	 */

	return (0);
}

static void selectinit(void *);
SYSINIT(fselect, SI_SUB_SYSCALLS, SI_ORDER_ANY, selectinit, NULL);

static void
selectinit(void *dummy __unused)
{

	selfd_zone = uma_zcreate("fselfd", sizeof(struct selfd), NULL, NULL,
	    NULL, NULL, UMA_ALIGN_PTR, 0);
}

static void selectuninit(void *);
SYSUNINIT(fselect, SI_SUB_SYSCALLS, SI_ORDER_ANY, selectuninit, NULL);

static void
selectuninit(void *dummy)
{

	uma_zdestroy(selfd_zone);
}

/*******************************************************************************
 * code for both of master and slave
 */

static int
count_slavefds(struct thread *td, struct pollfd *fds, nfds_t nfds,
	       nfds_t *nslavefds)
{
	nfds_t i;
	enum fmaster_fd_type fdtype;
	int error, n;

	n = 0;
	for (i = 0; i < nfds; i++) {
		error = fmaster_type_of_fd(td, fds[i].fd, &fdtype);
		if (error != 0)
			return (error);
		n += fdtype == FD_SLAVE ? 1 : 0;
	}

	*nslavefds = n;

	return (0);
}

static int
copy_fds(struct thread *td, enum fmaster_fd_type fdtype, struct pollfd *srcfds,
	 nfds_t nsrcfds, struct pollfd *destfds, nfds_t ndestfds)
{
	struct pollfd *pfd;
	nfds_t i, n;
	enum fmaster_fd_type t;
	int error;

	for (i = 0, n = 0; (i < nsrcfds) && (n < ndestfds); i++) {
		pfd = &srcfds[i];
		error = fmaster_type_of_fd(td, pfd->fd, &t);
		if (error != 0)
			return (error);
		if (t != fdtype)
			continue;
		memcpy(&destfds[n], pfd, sizeof(*pfd));
		n++;
	}

	return (0);
}

static int
merge_results(struct thread *td, struct pollfd *fds, nfds_t nfds,
	      struct pollfd *slavefds, nfds_t nslavefds,
	      struct pollfd *masterfds, nfds_t nmasterfds)
{
	struct pollfd *p, *pfd;
	nfds_t i, masterfdspos, slavefdspos;
	enum fmaster_fd_type fdtype;
	int error;

	for (i = masterfdspos = slavefdspos = 0; i < nfds; i++) {
		pfd = &fds[i];
		error = fmaster_type_of_fd(td, pfd->fd, &fdtype);
		if (error != 0)
			return (error);
		switch (fdtype) {
		case FD_MASTER:
			p = &masterfds[masterfdspos];
			masterfdspos++;
			break;
		case FD_SLAVE:
			p = &slavefds[slavefdspos];
			slavefdspos++;
			break;
		case FD_CLOSED:
		default:
			return (EBADF);
		}
		pfd->revents = p->revents;
	}

	return (0);
}

static int
master_slave_poll(struct thread *td, struct pollfd *fds, nfds_t nfds,
		  int timeout)
{
	struct malloc_type *mt;
	struct pollfd *masterfds, *mhubfd, *pfd, *slavefds;
	nfds_t i, nmasterfds, nslavefds;
	size_t masterfdssize, slavefdssize;
	int error, master_retval, slave_retval;

	error = count_slavefds(td, fds, nfds, &nslavefds);
	if (error != 0)
		return (error);

	mt = M_TEMP;
	slavefdssize = sizeof(slavefds[0]) * nslavefds;
	slavefds = (struct pollfd *)malloc(slavefdssize, mt, M_WAITOK);
	if (slavefds == NULL)
		return (ENOMEM);
	error = copy_fds(td, FD_SLAVE, fds, nfds, slavefds, nslavefds);
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
	error = copy_fds(td, FD_MASTER, fds, nfds, masterfds, nmasterfds);
	if (error != 0)
		goto exit2;
	for (i = 0; i < nmasterfds; i++) {
		pfd = &masterfds[i];
		pfd->fd = fmaster_fds_of_thread(td)[pfd->fd].fd_local;
	}
	mhubfd = &masterfds[nmasterfds];
	mhubfd->fd = fmaster_rfd_of_thread(td);
	mhubfd->events = POLLIN;
	mhubfd->revents = 0;

	error = sys_poll(td, masterfds, nmasterfds + 1, timeout);
	if (error != 0)
		goto exit2;
	master_retval = td->td_retval[0];

	error = fmaster_write_command(td, POLL_END);
	if (error != 0)
		goto exit2;
	error = read_result(td, POLL_ENDED, slavefds, nslavefds);
	if (error != 0)
		goto exit2;
	slave_retval = td->td_retval[0];

	error = merge_results(td, fds, nfds, slavefds, nslavefds, masterfds,
			      nmasterfds);
	if (error != 0)
		goto exit2;
	td->td_retval[0] = master_retval + slave_retval;

exit2:
	free(masterfds, mt);
exit1:
	free(slavefds, mt);

	return (0);
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
log_args(struct thread *td, struct pollfd *fds, nfds_t nfds)
{
	struct pollfd *pfd;
	nfds_t i;
	pid_t pid;
	enum fmaster_fd_type fdtype;
	int error, fd, lfd;
	short events;
	const char *sfdtype;
	char sevents[256];

	pid = td->td_proc->p_pid;
	for (i = 0; i < nfds; i++) {
		pfd = &fds[i];
		fd = pfd->fd;
		error = fmaster_type_of_fd(td, fd, &fdtype);
		if (error != 0)
			return (error);
		sfdtype = fdtype == FD_MASTER ? "master"
					      : fdtype == FD_SLAVE ? "slave"
								   : "closed";
		lfd = fmaster_fds_of_thread(td)[fd].fd_local;
		events = pfd->events;
		events_to_string(sevents, sizeof(sevents), events);
		log(LOG_DEBUG,
		    "fmaster[%d]: poll: fds[%d]: fd=%d (%s: %d), events=%d (%s)"
		    ", revents=%d\n",
		    pid, i, fd, sfdtype, lfd, events, sevents, pfd->revents);
	}

	return (0);
}

static int
detect_side(struct thread *td, struct pollfd *fds, nfds_t nfds,
	    enum fmaster_side *side)
{
	nfds_t i;
	enum fmaster_fd_type fdtype;
	int error;

	*side = 0;
	for (i = 0; i < nfds; i++) {
		error = fmaster_type_of_fd(td, fds[i].fd, &fdtype);
		if (error != 0)
			return (error);
		switch (fdtype) {
		case FD_MASTER:
			*side |= side_master;
			break;
		case FD_SLAVE:
			*side |= side_slave;
			break;
		case FD_CLOSED:
		default:
			return (EBADF);
		}
		if (*side == side_both)
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
	int error;

	nfds = uap->nfds;
	size = sizeof(*fds) * nfds;
	mt = M_TEMP;
	fds = (struct pollfd *)malloc(size, mt, M_WAITOK);
	if (fds == NULL)
		return (ENOMEM);
	error = copyin(uap->fds, fds, size);
	if (error != 0)
		goto exit;
	error = log_args(td, fds, nfds);
	if (error != 0)
		goto exit;

	error = detect_side(td, fds, nfds, &side);
	if (error != 0)
		goto exit;
	switch (side) {
	case side_master:
		error = master_poll(td, fds, nfds, uap->timeout);
		break;
	case side_slave:
		error = slave_poll(td, uap, fds);
		break;
	case side_both:
		error = master_slave_poll(td, fds, nfds, uap->timeout);
		break;
	default:
		error = EBADF;
		break;
	}
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
	const char *name = "poll";

	log(LOG_DEBUG,
	    "fmaster[%d]: %s: started: fds=%p, nfds=%d, timeout=%d\n",
	    td->td_proc->p_pid, name, uap->fds, uap->nfds, uap->timeout);
	microtime(&time_start);

	error = fmaster_poll_main(td, uap);

	fmaster_log_syscall_end(td, name, &time_start, error);

	return (error);
}

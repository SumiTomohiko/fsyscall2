#include <sys/param.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/select.h>
#include <sys/selinfo.h>
#include <sys/systm.h>

#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/select.h>
#include <sys/fmaster/fmaster_proto.h>

/*******************************************************************************
 * select(2) implementation for the master.
 */

static int
map_to_virtual_fd(struct thread *td, int nfds, const fd_set *local_fds,
		  fd_set *fds)
{
	struct malloc_type *mt = M_TEMP;
	enum fmaster_file_place place;
	int error, *l2v, lfd, vfd;

	l2v = (int *)malloc(sizeof(int) * nfds, mt, M_ZERO | M_WAITOK);
	if (l2v == NULL)
		return (ENOMEM);
	for (vfd = 0; vfd < FILES_NUM; vfd++) {
		error = fmaster_get_vnode_info(td, vfd, &place, &lfd);
		switch (error) {
		case 0:
			break;
		case EBADF:
			continue;
		default:
			goto exit;
		}
		if (place == FFP_MASTER)
			l2v[lfd] = vfd;
	}

	FD_ZERO(fds);
	for (lfd = 0; lfd < nfds; lfd++)
		if (FD_ISSET(lfd, local_fds))
			FD_SET(l2v[lfd], fds);

	error = 0;
exit:
	free(l2v, mt);

	return (error);
}

static int
map_to_local_fd(struct thread *td, int nfds, const fd_set *fds, int *nd, fd_set *local_fds)
{
	int error, fd, local_fd, max_fd;

	max_fd = 0;
	FD_ZERO(local_fds);

	for (fd = 0; fd < nfds; fd++)
		if (FD_ISSET(fd, fds)) {
			error = fmaster_get_vnode_info(td, fd, NULL, &local_fd);
			if (error != 0)
				return (error);
			max_fd = MAX(max_fd, local_fd);
			FD_SET(local_fd, local_fds);
		}

	*nd = MAX(*nd, max_fd + 1);

	return (0);
}

static int
count_fds(int nfds, fd_set *fds)
{
	int fd, n;

	n = 0;
	for (fd = 0; fd < nfds; fd++)
		n += FD_ISSET(fd, fds) ? 1 : 0;

	return (n);
}

static void
fd_set_to_kevent(struct kevent *kev, short filter, int nfds, const fd_set *fds)
{
	int fd;

	for (fd = 0; fd < nfds; fd++)
		if (FD_ISSET(fd, fds)) {
			EV_SET(kev, fd, filter, EV_ADD | EV_CLEAR | EV_ENABLE,
			       0, 0, NULL);
			kev++;
		}
}

static void
kevent_to_fd_set(fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
		 int nevents, const struct kevent *eventlist)
{
	const struct kevent *kev;
	fd_set *fds;
	int i;

	FD_ZERO(readfds);
	FD_ZERO(writefds);
	FD_ZERO(exceptfds);

	for (i = 0; i < nevents; i++) {
		kev = &eventlist[i];
		switch (kev->filter) {
		case EVFILT_READ:
			fds = readfds;
			break;
		case EVFILT_WRITE:
			fds = writefds;
			break;
		default:
			panic("invalid filter: %d", kev->filter);
		}
		FD_SET(kev->ident, fds);
	}
}

static int
kevent_select(struct thread *td, int nfds, fd_set *readfds, fd_set *writefds,
	      fd_set *exceptfds, struct timeval *timeout)
{
	struct kevent *changelist, *eventlist;
	struct timespec *pts, ts;
	size_t size;
	int error, nevents, nexceptfds, nkev, nreadfds, nwritefds;

	nreadfds = count_fds(nfds, readfds);
	nwritefds = count_fds(nfds, writefds);
	nexceptfds = count_fds(nfds, exceptfds);
	if (0 < nexceptfds)
		return (EOPNOTSUPP);
	nkev = nreadfds + nwritefds;

	size = sizeof(changelist[0]) * nkev;
	changelist = (struct kevent *)fmaster_malloc(td, size);
	if (changelist == NULL)
		return (ENOMEM);
	fd_set_to_kevent(&changelist[0], EVFILT_READ, nfds, readfds);
	fd_set_to_kevent(&changelist[nreadfds], EVFILT_WRITE, nfds, writefds);

	eventlist = (struct kevent *)fmaster_malloc(td, size);
	if (eventlist == NULL)
		return (ENOMEM);

	if (timeout != NULL) {
		ts.tv_sec = timeout->tv_sec;
		ts.tv_nsec = timeout->tv_usec;
		pts = &ts;
	}
	else
		pts = NULL;

	error = fmaster_do_kevent(td, changelist, nkev, eventlist, &nevents,
				  pts);
	if (error != 0)
		return (error);

	kevent_to_fd_set(readfds, writefds, exceptfds, nevents, eventlist);

	return (0);
}

static int
select_master(struct thread *td, int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
	fd_set ex, in, ou;
	int error, nd;

	nd = 0;
#define	MAP_TO_LOCAL_FD(fds, local_fds)	do {				\
	error = map_to_local_fd(td, nfds, (fds), &nd, &(local_fds));	\
	if (error != 0)							\
		return (error);						\
} while (0)
	MAP_TO_LOCAL_FD(readfds, in);
	MAP_TO_LOCAL_FD(writefds, ou);
	MAP_TO_LOCAL_FD(exceptfds, ex);
#undef	MAP_TO_LOCAL_FD

	error = kevent_select(td, nd, &in, &ou, &ex, timeout);
	if (error != 0)
		return (error);

#define	MAP_TO_VIRTUAL_FD(local_fds, fds)	do {		\
	error = map_to_virtual_fd(td, nd, &(local_fds), (fds));	\
	if (error != 0)						\
		return (error);					\
} while (0)
	MAP_TO_VIRTUAL_FD(in, readfds);
	MAP_TO_VIRTUAL_FD(ou, writefds);
	MAP_TO_VIRTUAL_FD(ex, exceptfds);
#undef	MAP_TO_VIRTUAL_FD

	return (error);
}

/*******************************************************************************
 * select(2) implementation for the slave.
 */

static int
encode_fds(struct thread *td, int nfds, struct fd_set *fds, char *buf, size_t bufsize, payload_size_t *data_len)
{
	size_t pos;
	int error, fd, i, len;

	pos = 0;
	for (i = 0; i < nfds; i++) {
		if (!FD_ISSET(i, fds))
			continue;
		error = fmaster_get_vnode_info(td, i, NULL, &fd);
		if (error != 0)
			return (error);
		len = fsyscall_encode_int32(fd, buf + pos, bufsize - pos);
		if (len == -1)
			return (ENOMEM);
		pos += len;
	}

	*data_len = pos;

	return (0);
}

static int
write_call(struct thread *td, int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
	struct malloc_type *type;
	payload_size_t exceptfds_len, payload_size, readfds_len, writefds_len;
	unsigned long exceptfds_buf_len, readfds_buf_len, writefds_buf_len;
	int error, flags, nexceptfds, nexceptfds_len, nfds_len, nreadfds;
	int nreadfds_len, nwritefds, nwritefds_len, sec_len, timeout_len;
	int usec_len, wfd;
	char *exceptfds_buf, nexceptfds_buf[FSYSCALL_BUFSIZE_INT32];
	char nfds_buf[FSYSCALL_BUFSIZE_INT32];
	char nreadfds_buf[FSYSCALL_BUFSIZE_INT32];
	char nwritefds_buf[FSYSCALL_BUFSIZE_INT32];
	char *readfds_buf, sec_buf[FSYSCALL_BUFSIZE_INT64];
	char timeout_buf[FSYSCALL_BUFSIZE_INT32];
	char usec_buf[FSYSCALL_BUFSIZE_INT64], *writefds_buf;

	KASSERT(readfds != NULL, "readfds must be NULL.");
	KASSERT(writefds != NULL, "writefds must be NULL.");
	KASSERT(exceptfds != NULL, "exceptfds must be NULL.");

	nreadfds = fsyscall_count_fds(nfds, readfds);
	nwritefds = fsyscall_count_fds(nfds, writefds);
	nexceptfds = fsyscall_count_fds(nfds, exceptfds);

	error = 0;
	writefds_buf = exceptfds_buf = NULL;
	type = M_FMASTER;
	flags = M_WAITOK;
	readfds_buf_len = fsyscall_compute_fds_bufsize(nreadfds);
	readfds_buf = (char *)malloc(readfds_buf_len, type, flags);
	if (readfds_buf == NULL)
		return (ENOMEM);
	writefds_buf_len = fsyscall_compute_fds_bufsize(nwritefds);
	writefds_buf = (char *)malloc(writefds_buf_len, type, flags);
	if (writefds_buf == NULL) {
		error = ENOMEM;
		goto finally;
	}
	exceptfds_buf_len = fsyscall_compute_fds_bufsize(nexceptfds);
	exceptfds_buf = (char *)malloc(exceptfds_buf_len, type, flags);
	if (exceptfds_buf == NULL) {
		error = ENOMEM;
		goto finally;
	}

#define	ENCODE_INT32(n, buf, len)	do {			\
	len = fsyscall_encode_int32((n), (buf), sizeof(buf));	\
	if (len == -1) {					\
		error = ENOMEM;					\
		goto finally;					\
	}							\
} while (0)
	ENCODE_INT32(nfds, nfds_buf, nfds_len);
	ENCODE_INT32(nreadfds, nreadfds_buf, nreadfds_len);
	ENCODE_INT32(nwritefds, nwritefds_buf, nwritefds_len);
	ENCODE_INT32(nexceptfds, nexceptfds_buf, nexceptfds_len);
	/*
	 * One more idea
	 * *************
	 *
	 * The following field tells that timeout is NULL or not NULL. This
	 * field can have more roles. For example, timeout must be usually NULL
	 * (for blocking) or zero (for polling). So this field can tell that
	 * timeout is zero with the value of "2". Such way can decrease bytes.
	 */
	ENCODE_INT32(timeout != NULL ? 1 : 0, timeout_buf, timeout_len);
#undef	ENCODE_INT32
#define	ENCODE_FDS(fds, buf, buf_len, len)	do {			\
	error = encode_fds(td, nfds, (fds), (buf), (buf_len), &(len));	\
	if (error != 0)							\
		goto finally;						\
} while (0)
	ENCODE_FDS(readfds, readfds_buf, readfds_buf_len, readfds_len);
	ENCODE_FDS(writefds, writefds_buf, writefds_buf_len, writefds_len);
	ENCODE_FDS(exceptfds, exceptfds_buf, exceptfds_buf_len, exceptfds_len);
#undef	ENCODE_FDS
#define	ENCODE_INT64(n, buf, len) do {				\
	len = fsyscall_encode_int64((n), (buf), sizeof(buf));	\
	if (len == -1) {					\
		error = ENOMEM;					\
		goto finally;					\
	}							\
} while (0)
	if (timeout != NULL) {
		ENCODE_INT64(timeout->tv_sec, sec_buf, sec_len);
		ENCODE_INT64(timeout->tv_usec, usec_buf, usec_len);
	}
	else
		sec_len = usec_len = 0;
#undef	ENCODE_INT64

	payload_size = nfds_len + nreadfds_len + readfds_len + nwritefds_len +
		       writefds_len + nexceptfds_len + exceptfds_len +
		       timeout_len + sec_len + usec_len;
	error = fmaster_write_command(td, SELECT_CALL);
	if (error != 0)
		goto finally;
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		goto finally;
	wfd = fmaster_wfd_of_thread(td);
#define	WRITE(buf, len)	do {				\
	error = fmaster_write(td, wfd, (buf), (len));	\
	if (error != 0)					\
		goto finally;				\
} while (0)
	WRITE(nfds_buf, nfds_len);
	WRITE(nreadfds_buf, nreadfds_len);
	WRITE(readfds_buf, readfds_len);
	WRITE(nwritefds_buf, nwritefds_len);
	WRITE(writefds_buf, writefds_len);
	WRITE(nexceptfds_buf, nexceptfds_len);
	WRITE(exceptfds_buf, exceptfds_len);
	WRITE(timeout_buf, timeout_len);
	WRITE(sec_buf, sec_len);
	WRITE(usec_buf, usec_len);
#undef	WRITE

finally:
	free(exceptfds_buf, type);
	free(writefds_buf, type);
	free(readfds_buf, type);

	return (error);
}

static int
read_fds(struct thread *td, fd_set *fds, payload_size_t *len)
{
	payload_size_t nfds_len, payload_size, slave_fd_len;
	int error, local_fd, nfds, i, slave_fd;

	payload_size = 0;

	error = fmaster_read_int32(td, &nfds, &nfds_len);
	if (error != 0)
		return (error);
	payload_size += nfds_len;

	for (i = 0; i < nfds; i++) {
		error = fmaster_read_int32(td, &slave_fd, &slave_fd_len);
		if (error != 0)
			return (error);
		payload_size += slave_fd_len;

		error = fmaster_fd_of_slave_fd(td, slave_fd, &local_fd);
		if (error != 0)
			return (error);
		FD_SET(local_fd, fds);
	}

	*len = payload_size;

	return (0);
}

static int
read_result(struct thread *td, fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
	payload_size_t actual_payload_size, errnum_len, exceptfds_len;
	payload_size_t payload_size, readfds_len, retval_len, writefds_len;
	command_t cmd;
	int errnum, error, retval;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != SELECT_RETURN)
		return (EPROTO);
	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);
	error = fmaster_read_int32(td, &retval, &retval_len);
	if (error != 0)
		return (error);

	switch (retval) {
	case -1:
		error = fmaster_read_int32(td, &errnum, &errnum_len);
		if (error != 0)
			return (error);
		actual_payload_size = retval_len + errnum_len;
		if (payload_size != actual_payload_size)
			return (EPROTO);
		return (errnum);
	case 0:
		readfds_len = writefds_len = exceptfds_len = 0;
		break;
	default:
		FD_ZERO(readfds);
		FD_ZERO(writefds);
		FD_ZERO(exceptfds);
		error = read_fds(td, readfds, &readfds_len);
		if (error != 0)
			return (error);
		error = read_fds(td, writefds, &writefds_len);
		if (error != 0)
			return (error);
		error = read_fds(td, exceptfds, &exceptfds_len);
		if (error != 0)
			return (error);
		break;
	}
	actual_payload_size = retval_len + readfds_len + writefds_len +
			      exceptfds_len;
	if (payload_size != actual_payload_size)
		return (EPROTO);

	td->td_retval[0] = retval;

	return (0);
}

static int
select_slave(struct thread *td, int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
	int error;

	error = write_call(td, nfds, readfds, writefds, exceptfds, timeout);
	if (error != 0)
		return (error);
	error = read_result(td, readfds, writefds, exceptfds);
	if (error != 0)
		return (error);

	return (0);
}

/*******************************************************************************
 * shared part for both of the master and the slave.
 */

static int
detect_fd_side(struct thread *td, int nfds, fd_set *fds, bool *master, bool *slave)
{
	enum fmaster_file_place place;
	int error, fd;
	bool *p;

	if (fds == NULL)
		return (0);

	for (fd = 0; fd < nfds; fd++)
		if (FD_ISSET(fd, fds)) {
			error = fmaster_get_vnode_info(td, fd, &place, NULL);
			if (error != 0)
				return (error);
			p = place == FFP_MASTER ? master : slave;
			*p = true;
		}

	return (0);
}

static int
fmaster_select_main(struct thread *td, struct fmaster_select_args *uap)
{
	struct timeval *ptimeout, timeout;
	fd_set exceptfds, readfds, writefds;
	int (*f)(struct thread *, int, fd_set *, fd_set *, fd_set *,
		 struct timeval *);
	int error, nfds;
	bool side_master, side_slave;

	nfds = uap->nd;

#define	INIT_FDS(u, k)	do {					\
	if ((u) != NULL) {					\
		error = copyin((u), (k), sizeof(*k));		\
		if (error != 0)					\
			return (error);				\
	}							\
	else							\
		FD_ZERO(k);					\
} while (0)
	INIT_FDS(uap->in, &readfds);
	INIT_FDS(uap->ou, &writefds);
	INIT_FDS(uap->ex, &exceptfds);
#undef	INIT_FDS
	if (uap->tv != NULL) {
		error = copyin(uap->tv, &timeout, sizeof(timeout));
		if (error != 0)
			return (error);
		ptimeout = &timeout;
	}
	else
		ptimeout = NULL;

	side_master = side_slave = false;
#define	DETECT_SIDE(fds)	do {				\
	error = detect_fd_side(td, nfds, &(fds), &side_master,	\
			       &side_slave);			\
	if (error != 0)						\
		return (error);					\
	if (side_master && side_slave)				\
		return (EBADF);					\
} while (0)
	DETECT_SIDE(readfds);
	DETECT_SIDE(writefds);
	DETECT_SIDE(exceptfds);
#undef	DETECT_SIDE

	f = side_master ? select_master : select_slave;
	error = f(td, nfds, &readfds, &writefds, &exceptfds, ptimeout);
	if (error != 0)
		return (error);

#define	COPYOUT(k, u)	do {					\
	if ((u) != NULL) {					\
		error = copyout((k), (u), sizeof(*(k)));	\
		if (error != 0)					\
			return (error);				\
	}							\
} while (0)
	COPYOUT(&readfds, uap->in);
	COPYOUT(&writefds, uap->ou);
	COPYOUT(&exceptfds, uap->ex);
#undef	COPYOUT

	return (0);
}

static int
log_fdset(struct thread *td, const char *name, int nd, fd_set *fdset)
{
	enum fmaster_file_place place;
	int error, fd, lfd;
	const char *fmt = "select: %s: %d (%s: %d)", *side;

	for (fd = 0; fd < nd; fd++)
		if (FD_ISSET(fd, fdset)) {
			error = fmaster_get_vnode_info(td, fd, &place, &lfd);
			if (error != 0)
				return (error);
			side = fmaster_str_of_place(place);
			fmaster_log(td, LOG_DEBUG, fmt, name, fd, side, lfd);
		}

	return (0);
}

static int
log_args(struct thread *td, struct fmaster_select_args *uap)
{
	fd_set ex, in, ou;
	int error, nd;

	nd = uap->nd;

#define	LOG_FDSET(fdset)	do {					\
	if (uap->fdset != NULL) {					\
		error = copyin(uap->fdset, &fdset, sizeof(fdset));	\
		if (error != 0)						\
			return (error);					\
		error = log_fdset(td, #fdset, nd, &fdset);		\
		if (error != 0)						\
			return (error);					\
	}								\
} while (0)
	LOG_FDSET(in);
	LOG_FDSET(ou);
	LOG_FDSET(ex);
#undef	LOG_FDSET

	return (0);
}

int
sys_fmaster_select(struct thread *td, struct fmaster_select_args *uap)
{
	struct timeval time_start;
	int error;

	fmaster_log(td, LOG_DEBUG,
		    "select: started: nd=%d, in=%p, ou=%p, ex=%p, tv=%p",
		    uap->nd, uap->in, uap->ou, uap->ex, uap->tv);
	microtime(&time_start);

	error = log_args(td, uap);
	if (error != 0)
		goto exit;
	error = fmaster_select_main(td, uap);

	fmaster_freeall(td);

exit:
	fmaster_log_syscall_end(td, "select", &time_start, error);

	return (error);
}

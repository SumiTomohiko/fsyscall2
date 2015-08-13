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
 * select(2) implementation for the master. This part came from the FreeBSD
 * source tree (sys/kern/sys_generic.c).
 */

struct seltd {
	STAILQ_HEAD(, selfd)	st_selq;	/* (k) List of selfds. */
	struct selfd		*st_free1;	/* (k) free fd for read set. */
	struct selfd		*st_free2;	/* (k) free fd for write set. */
	struct mtx		st_mtx;		/* Protects struct seltd */
	struct cv		st_wait;	/* (t) Wait channel. */
	int			st_flags;	/* (t) SELTD_ flags. */
};

struct selfd {
	STAILQ_ENTRY(selfd)	sf_link;	/* (k) fds owned by this td. */
	TAILQ_ENTRY(selfd)	sf_threads;	/* (f) fds on this selinfo. */
	struct selinfo		*sf_si;		/* (f) selinfo when linked. */
	struct mtx		*sf_mtx;	/* Pointer to selinfo mtx. */
	struct seltd		*sf_td;		/* (k) owning seltd. */
	void			*sf_cookie;	/* (k) fd or pollfd. */
};

static MALLOC_DEFINE(M_SELECT, "fsyssel", "select() buffer for fsyscall");
static uma_zone_t selfd_zone;

static void
seltdinit(struct thread *td)
{
	struct seltd *stp;

	if ((stp = td->td_sel) != NULL)
		goto out;
	td->td_sel = stp = malloc(sizeof(*stp), M_SELECT, M_WAITOK|M_ZERO);
	mtx_init(&stp->st_mtx, "fsellck", NULL, MTX_DEF);
	cv_init(&stp->st_wait, "fsyssel");
out:
	stp->st_flags = 0;
	STAILQ_INIT(&stp->st_selq);
}

static int
select_check_badfd(fd_set *fd_in, int nd, int ndu, int abi_nfdbits)
{
	char *addr, *oaddr;
	int b, i, res;
	uint8_t bits;

	if (nd >= ndu || fd_in == NULL)
		return (0);

	oaddr = NULL;
	bits = 0; /* silence gcc */
	for (i = nd; i < ndu; i++) {
		b = i / NBBY;
#if BYTE_ORDER == LITTLE_ENDIAN
		addr = (char *)fd_in + b;
#else
		addr = (char *)fd_in;
		if (abi_nfdbits == NFDBITS) {
			addr += rounddown(b, sizeof(fd_mask)) +
			    sizeof(fd_mask) - 1 - b % sizeof(fd_mask);
		} else {
			addr += rounddown(b, sizeof(uint32_t)) +
			    sizeof(uint32_t) - 1 - b % sizeof(uint32_t);
		}
#endif
		if (addr != oaddr) {
			res = *addr;
			oaddr = addr;
			bits = res;
		}
		if ((bits & (1 << (i % NBBY))) != 0)
			return (EBADF);
	}
	return (0);
}

static int select_flags[3] = {
    POLLRDNORM | POLLHUP | POLLERR,
    POLLWRNORM | POLLHUP | POLLERR,
    POLLRDBAND | POLLERR
};

static __inline int
selflags(fd_mask **ibits, int idx, fd_mask bit)
{
	int flags;
	int msk;

	flags = 0;
	for (msk = 0; msk < 3; msk++) {
		if (ibits[msk] == NULL)
			continue;
		if ((ibits[msk][idx] & bit) == 0)
			continue;
		flags |= select_flags[msk];
	}
	return (flags);
}

static __inline int
getselfd_cap(struct filedesc *fdp, int fd, struct file **fpp)
{
	struct file *fp;
#ifdef CAPABILITIES
	struct file *fp_fromcap;
	int error;
#endif

	if ((fp = fget_unlocked(fdp, fd)) == NULL)
		return (EBADF);
#ifdef CAPABILITIES
	/*
	 * If the file descriptor is for a capability, test rights and use
	 * the file descriptor references by the capability.
	 */
	error = cap_funwrap(fp, CAP_POLL_EVENT, &fp_fromcap);
	if (error) {
		fdrop(fp, curthread);
		return (error);
	}
	if (fp != fp_fromcap) {
		fhold(fp_fromcap);
		fdrop(fp, curthread);
		fp = fp_fromcap;
	}
#endif /* CAPABILITIES */
	*fpp = fp;
	return (0);
}

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

static __inline int
selsetbits(fd_mask **ibits, fd_mask **obits, int idx, fd_mask bit, int events)
{
	int msk;
	int n;

	n = 0;
	for (msk = 0; msk < 3; msk++) {
		if ((events & select_flags[msk]) == 0)
			continue;
		if (ibits[msk] == NULL)
			continue;
		if ((ibits[msk][idx] & bit) == 0)
			continue;
		/*
		 * XXX Check for a duplicate set.  This can occur because a
		 * socket calls selrecord() twice for each poll() call
		 * resulting in two selfds per real fd.  selrescan() will
		 * call selsetbits twice as a result.
		 */
		if ((obits[msk][idx] & bit) != 0)
			continue;
		obits[msk][idx] |= bit;
		n++;
	}

	return (n);
}

static int
selrescan(struct thread *td, fd_mask **ibits, fd_mask **obits)
{
	struct filedesc *fdp;
	struct selinfo *si;
	struct seltd *stp;
	struct selfd *sfp;
	struct selfd *sfn;
	struct file *fp;
	fd_mask bit;
	int fd, ev, n, idx;
	int error;

	fdp = td->td_proc->p_fd;
	stp = td->td_sel;
	n = 0;
	STAILQ_FOREACH_SAFE(sfp, &stp->st_selq, sf_link, sfn) {
		fd = (int)(uintptr_t)sfp->sf_cookie;
		si = sfp->sf_si;
		selfdfree(stp, sfp);
		/* If the selinfo wasn't cleared the event didn't fire. */
		if (si != NULL)
			continue;
		error = getselfd_cap(fdp, fd, &fp);
		if (error)
			return (error);
		idx = fd / NFDBITS;
		bit = (fd_mask)1 << (fd % NFDBITS);
		ev = fo_poll(fp, selflags(ibits, idx, bit), td->td_ucred, td);
		fdrop(fp, td);
		if (ev != 0)
			n += selsetbits(ibits, obits, idx, bit, ev);
	}
	stp->st_flags = 0;
	td->td_retval[0] = n;
	return (0);
}

static int
selscan(struct thread *td, fd_mask **ibits, fd_mask **obits, int nfd)
{
	struct filedesc *fdp;
	struct file *fp;
	fd_mask bit;
	int ev, flags, end, fd;
	int n, idx;
	int error;

	fdp = td->td_proc->p_fd;
	n = 0;
	for (idx = 0, fd = 0; fd < nfd; idx++) {
		end = imin(fd + NFDBITS, nfd);
		for (bit = 1; fd < end; bit <<= 1, fd++) {
			/* Compute the list of events we're interested in. */
			flags = selflags(ibits, idx, bit);
			if (flags == 0)
				continue;
			error = getselfd_cap(fdp, fd, &fp);
			if (error)
				return (error);
			selfdalloc(td, (void *)(uintptr_t)fd);
			ev = fo_poll(fp, flags, td->td_ucred, td);
			fdrop(fp, td);
			if (ev != 0)
				n += selsetbits(ibits, obits, idx, bit, ev);
		}
	}

	td->td_retval[0] = n;
	return (0);
}

#define	SELTD_PENDING	0x0001			/* We have pending events. */
#define	SELTD_RESCAN	0x0002			/* Doing a rescan. */

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
kern_select(struct thread *td, int nd, fd_set *fd_in, fd_set *fd_ou,
    fd_set *fd_ex, struct timeval *tvp, int abi_nfdbits)
{
	struct filedesc *fdp;
	/*
	 * The magic 2048 here is chosen to be just enough for FD_SETSIZE
	 * infds with the new FD_SETSIZE of 1024, and more than enough for
	 * FD_SETSIZE infds, outfds and exceptfds with the old FD_SETSIZE
	 * of 256.
	 */
	fd_mask s_selbits[howmany(2048, NFDBITS)];
	fd_mask *ibits[3], *obits[3], *selbits, *sbp;
	struct timeval atv, rtv, ttv;
	int error, lf, ndu, timo;
	u_int nbufbytes, ncpbytes, ncpubytes, nfdbits;

	if (nd < 0)
		return (EINVAL);
	fdp = td->td_proc->p_fd;
	ndu = nd;
	lf = fdp->fd_lastfile;
	if (nd > lf + 1)
		nd = lf + 1;

	error = select_check_badfd(fd_in, nd, ndu, abi_nfdbits);
	if (error != 0)
		return (error);
	error = select_check_badfd(fd_ou, nd, ndu, abi_nfdbits);
	if (error != 0)
		return (error);
	error = select_check_badfd(fd_ex, nd, ndu, abi_nfdbits);
	if (error != 0)
		return (error);

	/*
	 * Allocate just enough bits for the non-null fd_sets.  Use the
	 * preallocated auto buffer if possible.
	 */
	nfdbits = roundup(nd, NFDBITS);
	ncpbytes = nfdbits / NBBY;
	ncpubytes = roundup(nd, abi_nfdbits) / NBBY;
	nbufbytes = 0;
	if (fd_in != NULL)
		nbufbytes += 2 * ncpbytes;
	if (fd_ou != NULL)
		nbufbytes += 2 * ncpbytes;
	if (fd_ex != NULL)
		nbufbytes += 2 * ncpbytes;
	if (nbufbytes <= sizeof s_selbits)
		selbits = &s_selbits[0];
	else
		selbits = malloc(nbufbytes, M_SELECT, M_WAITOK);

	/*
	 * Assign pointers into the bit buffers and fetch the input bits.
	 * Put the output buffers together so that they can be bzeroed
	 * together.
	 */
	sbp = selbits;
#define	getbits(name, x) \
	do {								\
		if (name == NULL) {					\
			ibits[x] = NULL;				\
			obits[x] = NULL;				\
		} else {						\
			ibits[x] = sbp + nbufbytes / 2 / sizeof *sbp;	\
			obits[x] = sbp;					\
			sbp += ncpbytes / sizeof *sbp;			\
			memcpy(ibits[x], name, ncpubytes);		\
			bzero((char *)ibits[x] + ncpubytes,		\
			    ncpbytes - ncpubytes);			\
		}							\
	} while (0)
	getbits(fd_in, 0);
	getbits(fd_ou, 1);
	getbits(fd_ex, 2);
#undef	getbits

#if BYTE_ORDER == BIG_ENDIAN && defined(__LP64__)
	/*
	 * XXX: swizzle_fdset assumes that if abi_nfdbits != NFDBITS,
	 * we are running under 32-bit emulation. This should be more
	 * generic.
	 */
#define swizzle_fdset(bits)						\
	if (abi_nfdbits != NFDBITS && bits != NULL) {			\
		int i;							\
		for (i = 0; i < ncpbytes / sizeof *sbp; i++)		\
			bits[i] = (bits[i] >> 32) | (bits[i] << 32);	\
	}
#else
#define swizzle_fdset(bits)
#endif

	/* Make sure the bit order makes it through an ABI transition */
	swizzle_fdset(ibits[0]);
	swizzle_fdset(ibits[1]);
	swizzle_fdset(ibits[2]);

	if (nbufbytes != 0)
		bzero(selbits, nbufbytes / 2);

	if (tvp != NULL) {
		atv = *tvp;
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
		error = selscan(td, ibits, obits, nd);
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
		error = selrescan(td, ibits, obits);
		if (error || td->td_retval[0] != 0)
			break;
	}
	seltdclear(td);

done:
	/* select is not restarted after signals... */
	if (error == ERESTART)
		error = EINTR;
	if (error == EWOULDBLOCK)
		error = 0;

	/* swizzle bit order back, if necessary */
	swizzle_fdset(obits[0]);
	swizzle_fdset(obits[1]);
	swizzle_fdset(obits[2]);
#undef swizzle_fdset

#define	putbits(name, x)				\
	if (name != NULL)				\
		memcpy(name, obits[x], ncpubytes);
	if (error == 0) {
		putbits(fd_in, 0);
		putbits(fd_ou, 1);
		putbits(fd_ex, 2);
#undef putbits
	}
	if (selbits != &s_selbits[0])
		free(selbits, M_SELECT);

	return (error);
}

static int
map_to_virtual_fd(struct thread *td, int nfds, fd_set *local_fds, fd_set *fds)
{
	struct malloc_type *mt = M_TEMP;
	enum fmaster_file_place place;
	int error, *l2v, lfd, vfd;

	l2v = (int *)malloc(sizeof(int) * nfds, mt, M_ZERO | M_WAITOK);
	if (l2v == NULL)
		return (ENOMEM);
	for (vfd = 0; vfd < FILES_NUM; vfd++) {
		error = fmaster_get_vnode_info(td, vfd, &place, &lfd);
		if (error != 0)
			goto exit;
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
map_to_local_fd(struct thread *td, int nfds, fd_set *fds, int *nd, fd_set *local_fds)
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
			FD_SET(local_fd, fds);
		}

	*nd = MAX(*nd, max_fd + 1);

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

	error = kern_select(td, nd, &in, &ou, &ex, timeout, NFDBITS);
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

static struct mtx_pool *mtxpool_select;

static void
selectinit(void *dummy __unused)
{

	selfd_zone = uma_zcreate("fselfd", sizeof(struct selfd), NULL, NULL,
	    NULL, NULL, UMA_ALIGN_PTR, 0);
	mtxpool_select = mtx_pool_create("fsyssel mtxpool", 128, MTX_DEF);
}

SYSINIT(fsyssel, SI_SUB_SYSCALLS, SI_ORDER_ANY, selectinit, NULL);

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

#define	COPYOUT(u, k)	do {					\
	if ((u) != NULL) {					\
		error = copyout((u), (k), sizeof(*(k)));	\
		if (error == 0)					\
			return (error);				\
	}							\
} while (0)
	COPYOUT(uap->in, &readfds);
	COPYOUT(uap->ou, &writefds);
	COPYOUT(uap->ex, &exceptfds);
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
			side = place == FFP_MASTER ? "master" : "slave";
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

exit:
	fmaster_log_syscall_end(td, "select", &time_start, error);

	return (error);
}

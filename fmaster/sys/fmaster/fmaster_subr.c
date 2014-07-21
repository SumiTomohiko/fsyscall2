#include <sys/types.h>
#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/select.h>
#include <sys/selinfo.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>

static long
fmaster_subtract_timeval(const struct timeval *t1, const struct timeval *t2)
{

	return (1000000 * (t2->tv_sec - t1->tv_sec) + (t2->tv_usec - t1->tv_usec));
}

void
fmaster_log_spent_time(struct thread *td, const char *msg, const struct timeval *t1)
{
	struct timeval t2;
	long delta;

	microtime(&t2);
	delta = fmaster_subtract_timeval(t1, &t2);
	log(LOG_DEBUG, "fmaster[%d]: %s: %ld[usec]\n", td->td_proc->p_pid, msg, delta);
}

int
fmaster_is_master_file(struct thread *td, const char *path)
{
	int i;
	const char *dirs[] = {
		"/lib/",
		"/usr/lib/",
		"/usr/local/etc/fonts/conf.d/",
		"/usr/local/etc/pango/",
		"/usr/local/lib/",
		"/usr/local/share/fonts/",
		"/var/db/fontconfig/",
	};
	const char *files[] = {
		"/dev/urandom",
		"/etc/nsswitch.conf",
		"/etc/pwd.db",
		"/usr/local/etc/fonts/fonts.conf",
		"/usr/local/share/applications/gedit.desktop",
		"/var/db/dbus/machine-id",
		"/var/run/ld-elf.so.hints"
	};
	const char *s;

	for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
		s = dirs[i];
		if (strncmp(path, s, strlen(s)) == 0)
			return (1);
	}
	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		if (strcmp(path, files[i]) == 0)
			return (1);
	}

	return (0);
}

/*
 * In the unlikely case when user specified n greater then the last
 * open file descriptor, check that no bits are set after the last
 * valid fd.  We must return EBADF if any is set.
 *
 * There are applications that rely on the behaviour.
 *
 * nd is fd_lastfile + 1.
 */
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

static MALLOC_DEFINE(M_SELECT, "select", "select() buffer");

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

static uma_zone_t selfd_zone;

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

/*
 * Convert a select bit set to poll flags.
 *
 * The backend always returns POLLHUP/POLLERR if appropriate and we
 * return this as a set bit in any set.
 */
static int select_flags[3] = {
    POLLRDNORM | POLLHUP | POLLERR,
    POLLWRNORM | POLLHUP | POLLERR,
    POLLRDBAND | POLLERR
};

/*
 * Set the appropriate output bits given a mask of fired events and the
 * input bits originally requested.
 */
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

/*
 * Compute the fo_poll flags required for a fd given by the index and
 * bit position in the fd_mask array.
 */
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

static int	selscan(struct thread *, fd_mask **, fd_mask **, int);

/*
 * Perform the initial filedescriptor scan and register ourselves with
 * each selinfo.
 */
static int
selscan(td, ibits, obits, nfd)
	struct thread *td;
	fd_mask **ibits, **obits;
	int nfd;
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
selfdfree(struct seltd *stp, struct selfd *sfp)
{
	STAILQ_REMOVE(&stp->st_selq, sfp, selfd, sf_link);
	mtx_lock(sfp->sf_mtx);
	if (sfp->sf_si)
		TAILQ_REMOVE(&sfp->sf_si->si_tdlist, sfp, sf_threads);
	mtx_unlock(sfp->sf_mtx);
	uma_zfree(selfd_zone, sfp);
}

/*
 * Traverse the list of fds attached to this thread's seltd and check for
 * completion.
 */
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
fmaster_select(struct thread *td, int nd, fd_set *fd_in, fd_set *fd_ou,
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
			/*error = copyin(name, ibits[x], ncpubytes);	\
			if (error != 0)					\
				goto done;*/				\
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
	if (name)					\
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
do_select(struct thread *td, int d)
{
	struct timeval tv;
	fd_set fds;
	int error;

	tv.tv_sec = 8;
	tv.tv_usec = 0;
	FD_ZERO(&fds);
	FD_SET(d, &fds);

	error = fmaster_select(td, d + 1, &fds, NULL, NULL, &tv, NFDBITS);
	if (error != 0)
		return (error);
	if ((td->td_retval[0] != 1) || !FD_ISSET(d, &fds))
		return (ETIMEDOUT);

	return (error);
}

static void
die(struct thread *td, const char *cause)
{
	pid_t pid = td->td_proc->p_pid;

	log(LOG_INFO, "fmaster[%d]: die: %s\n", pid, cause);
	exit1(td, 1);
}

static int
do_readv(struct thread *td, int d, void *buf, size_t nbytes, int segflg)
{
	struct uio auio;
	struct iovec aiov;
	int error;

	if (INT_MAX < nbytes)
		return (EINVAL);

	aiov.iov_base = buf;
	aiov.iov_len = nbytes;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbytes;
	auio.uio_segflg = segflg;

	error = 0;
	while (0 < auio.uio_resid) {
		error = do_select(td, d);
		if (error != 0)
			die(td, "select");
		error = kern_readv(td, d, &auio);
		if (error != 0)
			return (error);
		if (td->td_retval[0] == 0)
			die(td, "readv");
	}

	return (error);
}

int
fmaster_read(struct thread *td, int d, void *buf, size_t nbytes)
{

	return do_readv(td, d, buf, nbytes, UIO_SYSSPACE);
}

static int
read_numeric_sequence(struct thread *td, int fd, char *buf, int bufsize, int *size)
{
	int error;
	char *p, *pend;

	pend = buf + bufsize;
	p = buf;
	error = fmaster_read(td, fd, p, sizeof(*p));
	while ((error == 0) && ((*p & 0x80) != 0) && (p + 1 < pend)) {
		p++;
		error = fmaster_read(td, fd, p, sizeof(*p));
	}
	if (error != 0)
		return (error);
	if ((*p & 0x80) != 0)
		return (EMSGSIZE);
	*size = (uintptr_t)p - (uintptr_t)buf + 1;
	return (0);
}

#define	IMPLEMENT_READ_X(type, name, bufsize, decode)		\
int								\
name(struct thread *td, type *dest, int *size)			\
{								\
	int error, fd;						\
	char buf[bufsize];					\
								\
	fd = fmaster_rfd_of_thread(td);				\
	error = read_numeric_sequence(				\
		td,						\
		fd,						\
		buf,						\
		array_sizeof(buf),				\
		size);						\
	if (error != 0)						\
		return (error);					\
								\
	return (decode(buf, *size, dest) != 0 ? EPROTO : 0);	\
}

IMPLEMENT_READ_X(
	int16_t,
	fmaster_read_int16,
	FSYSCALL_BUFSIZE_INT16,
	fsyscall_decode_int16)
IMPLEMENT_READ_X(
	int32_t,
	fmaster_read_int32,
	FSYSCALL_BUFSIZE_INT32,
	fsyscall_decode_int32)
IMPLEMENT_READ_X(
	int64_t,
	fmaster_read_int64,
	FSYSCALL_BUFSIZE_INT64,
	fsyscall_decode_int64)

int
fmaster_read_payload_size(struct thread *td, payload_size_t *dest)
{
	int _;

	return (fmaster_read_uint32(td, dest, &_));
}

int
fmaster_read_command(struct thread *td, command_t *dest)
{
	int _;

	return (fmaster_read_uint32(td, dest, &_));
}

static int
write_aio(struct thread *td, int d, const void *buf, size_t nbytes, enum uio_seg segflg)
{
	struct uio auio;
	struct iovec aiov;
	int error;

	if (INT_MAX < nbytes)
		return (EINVAL);

	/* Casting to uintptr_t is needed to escape the compiler warning. */
	aiov.iov_base = (void *)(uintptr_t)buf;
	aiov.iov_len = nbytes;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbytes;
	auio.uio_segflg = segflg;

	error = 0;
	while (((error == 0) || (error == EINTR)) && (0 < auio.uio_resid))
		error = kern_writev(td, d, &auio);

	return (error);
}

int
fmaster_write_from_userspace(struct thread *td, int d, const void *buf, size_t nbytes)
{
	return (write_aio(td, d, buf, nbytes, UIO_USERSPACE));
}

int
fmaster_write(struct thread *td, int d, const void *buf, size_t nbytes)
{
	return (write_aio(td, d, buf, nbytes, UIO_SYSSPACE));
}

static struct fmaster_data *
data_of_thread(struct thread *td)
{
	return ((struct fmaster_data *)(td->td_proc->p_emuldata));
}

int
fmaster_rfd_of_thread(struct thread *td)
{
	return (data_of_thread(td)->rfd);
}

int
fmaster_wfd_of_thread(struct thread *td)
{
	return (data_of_thread(td)->wfd);
}

struct fmaster_fd *
fmaster_fds_of_thread(struct thread *td)
{
	return (data_of_thread(td)->fds);
}

#define	IMPLEMENT_WRITE_X(type, name, bufsize, encode)	\
int							\
name(struct thread *td, type n)				\
{							\
	int len, wfd;					\
	char buf[bufsize];				\
							\
	len = encode(n, buf, array_sizeof(buf));	\
	if (len < 0)					\
		return (EMSGSIZE);			\
	wfd = fmaster_wfd_of_thread(td);		\
	return (fmaster_write(td, wfd, buf, len));	\
}

IMPLEMENT_WRITE_X(
		command_t,
		fmaster_write_command,
		FSYSCALL_BUFSIZE_COMMAND,
		fsyscall_encode_command)
IMPLEMENT_WRITE_X(
		int32_t,
		fmaster_write_int32,
		FSYSCALL_BUFSIZE_INT32,
		fsyscall_encode_int32)

int
fmaster_execute_return_generic32(struct thread *td, command_t expected_cmd)
{
	/**
	 * TODO: fmaster_execute_return_generic32 is very similar to
	 * fmaster_execute_return_generic64.
	 */
	int32_t ret;
	command_t cmd;
	uint32_t payload_size;
	int errnum, errnum_len, error, ret_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != expected_cmd)
		return (EPROTO);

	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_int32(td, &ret, &ret_len);
	if (error != 0)
		return (error);
	if (ret != -1) {
		if (payload_size != ret_len)
			return (EPROTO);
		td->td_retval[0] = ret;
		return (0);
	}

	error = fmaster_read_int32(td, &errnum, &errnum_len);
	if (error != 0)
		return (error);
	if (payload_size != ret_len + errnum_len)
		return (EPROTO);
	return (errnum);
}

int
fmaster_fd_of_slave_fd(struct thread *td, int slave_fd, int *local_fd)
{
	struct fmaster_fd *fd, *fds;
	int i;

	fds = fmaster_fds_of_thread(td);
	for (i = 0; i < FD_NUM; i++) {
		fd = &fds[i];
		if ((fd->fd_type == FD_SLAVE) || (fd->fd_local == slave_fd)) {
			*local_fd = i;
			return (0);
		}
	}

	return (EPROTO);
}

int
fmaster_execute_return_generic64(struct thread *td, command_t expected_cmd)
{
	int64_t ret;
	command_t cmd;
	uint32_t payload_size;
	int errnum, errnum_len, error, ret_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != expected_cmd)
		return (EPROTO);

	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_int64(td, &ret, &ret_len);
	if (error != 0)
		return (error);
	if (ret != -1) {
		if (payload_size != ret_len)
			return (EPROTO);
		td->td_retval[0] = ret & UINT32_MAX;
		td->td_retval[1] = ret >> 32;
		return (0);
	}

	error = fmaster_read_int32(td, &errnum, &errnum_len);
	if (error != 0)
		return (error);
	if (payload_size != ret_len + errnum_len)
		return (EPROTO);
	return (errnum);
}

int
fmaster_read_to_userspace(struct thread *td, int d, void *buf, size_t nbytes)
{

	return do_readv(td, d, buf, nbytes, UIO_USERSPACE);
}

static int
find_unused_fd(struct thread *td)
{
	struct fmaster_fd *fds;
	int i;

	fds = fmaster_fds_of_thread(td);
	for (i = 0; (i < FD_NUM) && (fds[i].fd_type != FD_CLOSED); i++);

	return (i);
}

enum fmaster_fd_type
fmaster_type_of_fd(struct thread *td, int d)
{
	return (fmaster_fds_of_thread(td)[d].fd_type);
}

int
fmaster_register_fd(struct thread *td, enum fmaster_fd_type type, int d, int *virtual_fd)
{
	struct fmaster_fd *fd;

	*virtual_fd = find_unused_fd(td);
	if (*virtual_fd == FD_NUM)
		return (EMFILE);
	fd = &fmaster_fds_of_thread(td)[*virtual_fd];
	fd->fd_type = type;
	fd->fd_local = d;

	return (0);
}

int
fmaster_return_fd(struct thread *td, enum fmaster_fd_type type, int d)
{
	int error, virtual_fd;

	error = fmaster_register_fd(td, type, d, &virtual_fd);
	if (error != 0)
		return (error);

	td->td_retval[0] = virtual_fd;

	return (0);
}

void
fmaster_close_fd(struct thread *td, int d)
{
	fmaster_fds_of_thread(td)[d].fd_type = FD_CLOSED;
}

static void selectinit(void *);
SYSINIT(select, SI_SUB_SYSCALLS, SI_ORDER_ANY, selectinit, NULL);
static void
selectinit(void *dummy __unused)
{

	selfd_zone = uma_zcreate("selfd", sizeof(struct selfd), NULL, NULL,
	    NULL, NULL, UMA_ALIGN_PTR, 0);
}

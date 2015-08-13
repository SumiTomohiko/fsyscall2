#include <sys/param.h>
#include <sys/event.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/systm.h>
#include <sys/time.h>

#include <fmaster/fmaster_proto.h>
#include <fsyscall/private/fmaster.h>

static void
fflags_to_str(char *buf, size_t bufsize, int filter, unsigned int fflags)
{
	static struct flag_definition defs_rw[] = {
		DEFINE_FLAG(NOTE_LOWAT)
	};
	static struct flag_definition defs_vnode[] = {
		DEFINE_FLAG(NOTE_DELETE),
		DEFINE_FLAG(NOTE_WRITE),
		DEFINE_FLAG(NOTE_EXTEND),
		DEFINE_FLAG(NOTE_ATTRIB),
		DEFINE_FLAG(NOTE_LINK),
		DEFINE_FLAG(NOTE_RENAME),
		DEFINE_FLAG(NOTE_REVOKE)
	};
	static struct flag_definition defs_proc[] = {
		DEFINE_FLAG(NOTE_EXIT),
		DEFINE_FLAG(NOTE_FORK),
		DEFINE_FLAG(NOTE_EXIT),
		DEFINE_FLAG(NOTE_TRACK),
		DEFINE_FLAG(NOTE_TRACKERR),
		DEFINE_FLAG(NOTE_CHILD)
	};
	static struct flag_definition defs_user[] = {
		DEFINE_FLAG(NOTE_FFNOP),
		DEFINE_FLAG(NOTE_FFAND),
		DEFINE_FLAG(NOTE_FFOR),
		DEFINE_FLAG(NOTE_FFCOPY),
		DEFINE_FLAG(NOTE_TRIGGER)
	};
	struct flag_definition* defs;
	int ndefs;

#define	SET_DEFINITION(a)	do {	\
	defs = (a);			\
	ndefs = array_sizeof((a));	\
} while (0)

	switch (filter) {
	case EVFILT_READ:
	case EVFILT_WRITE:
		SET_DEFINITION(defs_rw);
		break;
	case EVFILT_VNODE:
		SET_DEFINITION(defs_vnode);
		break;
	case EVFILT_PROC:
		SET_DEFINITION(defs_proc);
		break;
	case EVFILT_USER:
		SET_DEFINITION(defs_user);
		break;
	case EVFILT_AIO:
	case EVFILT_SIGNAL:
	case EVFILT_TIMER:
	case EVFILT_FS:
	case EVFILT_LIO:
	default:
		defs = NULL;
		ndefs = 0;
		break;
	}

#undef	SET_DEFINITION

	fmaster_chain_flags(buf, bufsize, fflags, defs, ndefs);
}

static void
flags_to_str(char *buf, size_t bufsize, unsigned short flags)
{
	static struct flag_definition defs[] = {
		DEFINE_FLAG(EV_ADD),
		DEFINE_FLAG(EV_DELETE),
		DEFINE_FLAG(EV_ENABLE),
		DEFINE_FLAG(EV_DISABLE),
		DEFINE_FLAG(EV_ONESHOT),
		DEFINE_FLAG(EV_CLEAR),
		DEFINE_FLAG(EV_RECEIPT),
		DEFINE_FLAG(EV_DISPATCH),
		DEFINE_FLAG(EV_SYSFLAGS),
		DEFINE_FLAG(EV_FLAG1),
		DEFINE_FLAG(EV_EOF),
		DEFINE_FLAG(EV_ERROR)
	};

	fmaster_chain_flags(buf, bufsize, flags, defs, array_sizeof(defs));
}

static const char *
get_filter_name(short filter)
{

	switch (filter) {
	case EVFILT_READ:	return "EVFILT_READ";
	case EVFILT_WRITE:	return "EVFILT_WRITE";
	case EVFILT_AIO:	return "EVFILT_AIO";
	case EVFILT_VNODE:	return "EVFILT_VNODE";
	case EVFILT_PROC:	return "EVFILT_PROC";
	case EVFILT_SIGNAL:	return "EVFILT_SIGNAL";
	case EVFILT_TIMER:	return "EVFILT_TIMER";
	case EVFILT_FS:		return "EVFILT_FS";
	case EVFILT_LIO:	return "EVFILT_LIO";
	case EVFILT_USER:	return "EVFILT_USER";
	default:		return "unknown filter";
	}
}

static void
timeout_to_str(char *buf, size_t bufsize, const struct timespec *t)
{
	const char *fmt = "tv_sec=%ld, tv_nsec=%ld";

	if (t == NULL) {
		snprintf(buf, bufsize, "null");
		return;
	}

	snprintf(buf, bufsize, fmt, t->tv_sec, t->tv_nsec);
}

static int
log_args(struct thread *td, struct fmaster_kevent_args *uap,
	 struct kevent *kchangelist, struct timespec *ktimeout)
{
	struct kevent *ke;
	int flt, i, nchanges;
	const char *filter_name;
	const char *header = "kevent";
	char fflags_str[256], flags_str[256], timeout_str[256];

	nchanges = uap->nchanges;
	timeout_to_str(timeout_str, sizeof(timeout_str), ktimeout);
	fmaster_log(td, LOG_DEBUG,
		    "%s: fd=%d, changelist=%p, nchanges=%d, eventlist=%p, neven"
		    "ts=%d, timeout=%p (%s)",
		    uap->fd, uap->changelist, nchanges, uap->eventlist,
		    uap->nevents, uap->timeout, timeout_str);

	if ((kchangelist == NULL) || (nchanges == 0))
		return (0);
	for (i = 0; i < nchanges; i++) {
		ke = &kchangelist[i];

		flt = ke->filter;
		filter_name = get_filter_name(flt);
		flags_to_str(flags_str, sizeof(flags_str), ke->flags);
		fflags_to_str(fflags_str, sizeof(fflags_str), flt, ke->fflags);

		fmaster_log(td, LOG_DEBUG,
			    "%s: changelist[%d]: ident=%lu, filter=%d (%s), fla"
			    "gs=0x%x (%s), fflags=0x%x (%s), data=%ld, udata=%p"
			    "",
			    header, i, ke->ident, flt, filter_name,
			    0xff & ke->flags, flags_str, 0xffff & ke->fflags,
			    fflags_str, ke->data, ke->udata);
	}

	return (0);
}

#if 0
static int
add_changelist(struct thread *td, struct payload *payload, int nchanges,
	       struct kevent *kchangelist)
{
	struct kevent kev, *pkev;
	uintptr_t ident;
	int error, i;
	short filter;

	for (i = 0; i < nchanges; i++) {
		pkev = &kchangelist[i];
		filter = pkev->filter;

		switch (filter) {
		case EVFILT_READ:
		case EVFILT_WRITE:
		case EVFILT_VNODE:
			ident = fmaster_fds_of_thread(td)[pkev->ident].fd_local;
			break;
		case EVFILT_AIO:
		case EVFILT_SIGNAL:
		case EVFILT_TIMER:
		case EVFILT_FS:
		case EVFILT_LIO:
		case EVFILT_USER:
		default:
			ident = pkev->ident;
			break;
		}
		kev.ident = ident;
		kev.filter = filter;
		kev.flags = pkev->flags;
		kev.fflags = pkev->fflags;
		kev.data = pkev->data;
		kev.udata = pkev->udata;

		error = fsyscall_payload_add_kevent(payload, &kev);
		if (error != 0)
			return (error);
	}

	return (0);
}

static int
build_payload(struct thread *td, struct fmaster_kevent_args *uap,
	      struct kevent *kchangelist, struct payload *payload)
{
	const struct timespec *timeout;
	int changelist_code, error, lfd, nchanges, timeout_code;

	lfd = fmaster_fds_of_thread(td)[uap->fd].fd_local;
	error = fsyscall_payload_add_int(payload, lfd);
	if (error != 0)
		return (error);
	nchanges = uap->nchanges;
	error = fsyscall_payload_add_int(payload, nchanges);
	if (error != 0)
		return (error);
	changelist_code = kchangelist != NULL ? KEVENT_CHANGELIST_NOT_NULL
					      : KEVENT_CHANGELIST_NULL;
	error = fsyscall_payload_add_int(payload, changelist_code);
	if (error != 0)
		return (error);
	if (kchangelist != NULL) {
		error = add_changelist(td, payload, nchanges, kchangelist);
		if (error != 0)
			return (error);
	}
	error = fsyscall_payload_add_int(payload, uap->nevents);
	if (error != 0)
		return (error);
	timeout = uap->timeout;
	timeout_code = timeout != NULL ? KEVENT_TIMEOUT_NOT_NULL
				       : KEVENT_TIMEOUT_NULL;
	error = fsyscall_payload_add_int(payload, timeout_code);
	if (error != 0)
		return (error);
	if (timeout != NULL) {
		error = fsyscall_payload_add_time(payload, timeout->tv_sec);
		if (error != 0)
			return (error);
		error = fsyscall_payload_add_long(payload, timeout->tv_nsec);
		if (error != 0)
			return (error);
	}

	return (0);
}

static int
execute_call(struct thread *td, struct fmaster_kevent_args *uap,
	     struct kevent *kchangelist)
{
	struct payload *payload;
	int error;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);

	error = build_payload(td, uap, kchangelist, payload);
	if (error != 0)
		goto exit;
	error = fmaster_write_payloaded_command(td, KEVENT_CALL, payload);
	if (error != 0)
		goto exit;

	error = 0;
exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
read_kevent(struct thread *td, struct kevent *kev, payload_size_t *len)
{
	uintptr_t ident, master_ident;
	payload_size_t data_len, fflags_len, filter_len, flags_len, ident_len;
	payload_size_t udata_len;
	int error, fd, udata_code;
	short filter;

	error = fmaster_read_ulong(td, &ident, &ident_len);
	if (error != 0)
		return (error);
	error = fmaster_read_short(td, &filter, &filter_len);
	if (error != 0)
		return (error);
	switch (filter) {
	case EVFILT_READ:
	case EVFILT_WRITE:
	case EVFILT_VNODE:
		error = fmaster_fd_of_slave_fd(td, ident, &fd);
		if (error != 0)
			return (error);
		master_ident = fd;
		break;
	case EVFILT_AIO:
	case EVFILT_SIGNAL:
	case EVFILT_TIMER:
	case EVFILT_FS:
	case EVFILT_LIO:
	case EVFILT_USER:
	default:
		master_ident = ident;
		break;
	}
	kev->ident = master_ident;
	kev->filter = filter;
	error = fmaster_read_ushort(td, &kev->flags, &flags_len);
	if (error != 0)
		return (error);
	error = fmaster_read_uint(td, &kev->fflags, &fflags_len);
	if (error != 0)
		return (error);
	error = fmaster_read_long(td, &kev->data, &data_len);
	if (error != 0)
		return (error);
	error = fmaster_read_int(td, &udata_code, &udata_len);
	if (error != 0)
		return (error);
	switch (udata_code) {
	case KEVENT_UDATA_NULL:
		kev->udata = NULL;
		break;
	case KEVENT_UDATA_NOT_NULL:
	default:
		return (EPROTO);
	}

	*len = ident_len + filter_len + flags_len + fflags_len + data_len +
	       udata_len;

	return (0);
}

static int
execute_return(struct thread *td, struct fmaster_kevent_args *uap)
{
	struct malloc_type *mt;
	struct kevent *eventlist;
	payload_size_t actual_payload_size, errnum_len, eventlist_len, kev_len;
	payload_size_t payload_size, retval_len;
	size_t size;
	command_t cmd;
	int errnum, error, i, retval;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != KEVENT_RETURN)
		return (EPROTO);
	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);
	error = fmaster_read_int32(td, &retval, &retval_len);
	if (error != 0)
		return (error);

	if (retval == -1) {
		error = fmaster_read_int32(td, &errnum, &errnum_len);
		if (error != 0)
			return (error);
		actual_payload_size = retval_len + errnum_len;
		if (payload_size != actual_payload_size)
			return (EPROTO);
		return (errnum);
	}

	size = sizeof(*eventlist) * retval;
	mt = M_TEMP;
	eventlist = (struct kevent *)malloc(size, mt, M_WAITOK);
	eventlist_len = 0;
	for (i = 0; i < retval; i++) {
		error = read_kevent(td, &eventlist[i], &kev_len);
		if (error != 0)
			goto exit;
		eventlist_len += kev_len;
	}

	actual_payload_size = retval_len + eventlist_len;
	if (payload_size != actual_payload_size) {
		error = EPROTO;
		goto exit;
	}

	error = copyout(eventlist, uap->eventlist, size);
	if (error != 0)
		goto exit;
	td->td_retval[0] = retval;
	error = 0;
exit:
	free(eventlist, mt);

	return (error);
}
#endif

static int
copyin_changelist(struct kevent *changelist, int nchanges,
		  struct malloc_type *mt, struct kevent **kchangelist)
{
	unsigned long size;
	int error;

	if (changelist == NULL) {
		*kchangelist = NULL;
		return (0);
	}

	size = sizeof(*changelist) * nchanges;
	*kchangelist = (struct kevent *)malloc(size, mt, M_WAITOK);
	if (*kchangelist == NULL)
		return (ENOMEM);
	error = copyin(changelist, *kchangelist, size);
	if (error != 0)
		return (error);

	return (0);
}

static int
detect_fd(struct thread *td, struct kevent *kchangelist, int nchanges,
	  enum fmaster_file_place which)
{
	struct kevent *kev;
	enum fmaster_file_place place;
	int error, i;

	for (i = 0; i < nchanges; i++) {
		kev = &kchangelist[i];
		switch (kev->filter) {
		case EVFILT_READ:
		case EVFILT_WRITE:
		case EVFILT_VNODE:
			error = fmaster_get_vnode_info(td, kev->ident, &place,
						       NULL);
			if (error != 0)
				return (error);
			if (place != which)
				return (EBADF);
			break;
		case EVFILT_AIO:
		case EVFILT_SIGNAL:
		case EVFILT_TIMER:
		case EVFILT_FS:
		case EVFILT_LIO:
		case EVFILT_USER:
		default:
			break;
		}
	}

	return (0);
}

struct copyio_bonus {
	struct thread *td;
	struct kevent *kchangelist;
	struct kevent *eventlist;
	int ncopyined;
	int ncopyouted;
};

static int
kevent_copyout(void *arg, struct kevent *kevp, int count)
{
	struct thread *td;
	struct malloc_type *mt;
	struct kevent *p, *tmp;
	struct copyio_bonus *bonus;
	size_t size;
	int error, fd, i;

	size = sizeof(kevp[0]) * count;
	mt = M_TEMP;
	tmp = (struct kevent *)malloc(size, mt, M_WAITOK);
	if (tmp == NULL)
		return (ENOMEM);
	memcpy(tmp, kevp, size);

	bonus = (struct copyio_bonus *)arg;
	td = bonus->td;
	for (i = 0; i < count; i++) {
		p = &kevp[i];
		switch (p->filter) {
		case EVFILT_READ:
		case EVFILT_WRITE:
		case EVFILT_VNODE:
			error = fmaster_fd_of_master_fd(td, p->ident, &fd);
			if (error != 0)
				goto exit;
			p->ident = fd;
			break;
		case EVFILT_AIO:
		case EVFILT_SIGNAL:
		case EVFILT_TIMER:
		case EVFILT_FS:
		case EVFILT_LIO:
		case EVFILT_USER:
		default:
			break;
		}
	}
	error = copyout(tmp, &bonus->eventlist[bonus->ncopyouted], size);
	if (error != 0)
		goto exit;

	bonus->ncopyouted += count;
	error = 0;
exit:
	free(tmp, mt);

	return (error);
}

static int
kevent_copyin(void *arg, struct kevent *kevp, int count)
{
	struct thread *td;
	struct kevent *p;
	struct copyio_bonus *bonus;
	int error, i, lfd;

	bonus = (struct copyio_bonus *)arg;
	p = &bonus->kchangelist[bonus->ncopyined];
	memcpy(kevp, p, sizeof(kevp[0]) * count);

	td = bonus->td;
	for (i = 0; i < count; i++) {
		p = &kevp[i];
		switch (p->filter) {
		case EVFILT_READ:
		case EVFILT_WRITE:
		case EVFILT_VNODE:
			error = fmaster_get_vnode_info(td, p->ident, NULL,
						       &lfd);
			if (error != 0)
				return (error);
			p->ident = lfd;
			break;
		case EVFILT_AIO:
		case EVFILT_SIGNAL:
		case EVFILT_TIMER:
		case EVFILT_FS:
		case EVFILT_LIO:
		case EVFILT_USER:
		default:
			break;
		}
	}

	bonus->ncopyined += count;

	return (0);
}

static int
fmaster_kevent_main(struct thread *td, struct fmaster_kevent_args *uap)
{
	struct malloc_type *mt;
	struct kevent *kchangelist;
	struct timespec *ktimeout, timeout;
	struct copyio_bonus bonus;
	struct kevent_copyops ops;
	enum fmaster_file_place place;
	int error, lfd, nchanges;

	nchanges = uap->nchanges;
	mt = M_TEMP;
	error = copyin_changelist(uap->changelist, nchanges, mt, &kchangelist);
	if (error != 0)
		return (error);
	if (uap->timeout != NULL) {
		ktimeout = &timeout;
		error = copyin(uap->timeout, ktimeout, sizeof(timeout));
		if (error != 0)
			goto exit;
	}
	else
		ktimeout = NULL;
	error = log_args(td, uap, kchangelist, ktimeout);
	if (error != 0)
		goto exit;

	error = fmaster_get_vnode_info(td, uap->fd, &place, &lfd);
	if (error != 0)
		goto exit;
	if (place != FFP_MASTER) {
		error = EBADF;
		goto exit;
	}
	error = detect_fd(td, kchangelist, nchanges, FFP_MASTER);
	if (error != 0)
		goto exit;
	bonus.td = td;
	bonus.kchangelist = kchangelist;
	bonus.eventlist = uap->eventlist;
	bonus.ncopyined = bonus.ncopyouted = 0;
	ops.arg = &bonus;
	ops.k_copyout = kevent_copyout;
	ops.k_copyin = kevent_copyin;
	error = kern_kevent(td, lfd, nchanges, uap->nevents, &ops, ktimeout);
	if (error != 0)
		goto exit;

	error = 0;
exit:
	free(kchangelist, mt);

	return (error);
}

int
sys_fmaster_kevent(struct thread *td, struct fmaster_kevent_args *uap)
{
	struct timeval time_end, time_start;
	long t;
	int error;
	const char *name = "kevent";

	fmaster_log(td, LOG_DEBUG, "%s: started", name);
	microtime(&time_start);

	error = fmaster_kevent_main(td, uap);

	microtime(&time_end);
	t = fmaster_subtract_timeval(&time_start, &time_end);
	fmaster_log(td, LOG_DEBUG,
		    "%s: ended: error=%d, retval=%ld: %ld[usec]",
		    name, error, td->td_retval[0], t);

	return (error);
}

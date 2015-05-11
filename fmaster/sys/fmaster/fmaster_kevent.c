#include <sys/param.h>
#include <sys/event.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/time.h>

#include <fmaster/fmaster_proto.h>
#include <fsyscall/private/fmaster.h>

typedef unsigned int flag_t;

struct flag_definition {
	flag_t value;
	const char *name;
};

#define	DEFINE_FLAG(name)	{ name, #name }

#define	array_sizeof(a)		(sizeof(a) / sizeof(a[0]))

static void
chain_flags(char *buf, size_t bufsize, flag_t flags, struct flag_definition defs[], size_t ndefs)
{
	int i, len, size;
	const char *sep;

	buf[0] = '\0';
	len = 0;
	sep = "";
	for (i = 0; i < ndefs; i++) {
		if ((flags & defs[i].value) == 0)
			continue;
		size = bufsize - len;
		len += snprintf(&buf[len], size, "%s%s", sep, defs[i].name);
		sep = "|";
	}
	if (buf[0] == '\0')
		snprintf(buf, bufsize, "nothing");
}

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

	chain_flags(buf, bufsize, fflags, defs, ndefs);
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

	chain_flags(buf, bufsize, flags, defs, array_sizeof(defs));
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
	 struct kevent *kchangelist)
{
	struct kevent *ke;
	pid_t pid;
	int flt, i, nchanges;
	const char *filter_name;
	char fflags_str[256], flags_str[256], header[64], timeout_str[256];

	pid = td->td_proc->p_pid;
	snprintf(header, sizeof(header), "fmaster[%d]: kevent", pid);

	nchanges = uap->nchanges;
	timeout_to_str(timeout_str, sizeof(timeout_str), uap->timeout);
	log(LOG_DEBUG,
	    "%s: fd=%d, changelist=%p, nchanges=%d, eventlist=%p, nevents=%d, t"
	    "imeout=%p (%s)\n",
	    header, uap->fd, uap->changelist, nchanges, uap->eventlist,
	    uap->nevents, uap->timeout, timeout_str);

	if ((kchangelist == NULL) || (nchanges == 0))
		return (0);
	for (i = 0; i < nchanges; i++) {
		ke = &kchangelist[i];

		flt = ke->filter;
		filter_name = get_filter_name(flt);
		flags_to_str(flags_str, sizeof(flags_str), ke->flags);
		fflags_to_str(fflags_str, sizeof(fflags_str), flt, ke->fflags);

		log(LOG_DEBUG,
		    "%s: changelist[%d]: ident=%lu, filter=%d (%s), flags=0x%x "
		    "(%s), fflags=0x%x (%s), data=%ld, udata=%p\n",
		    header, i, ke->ident, flt, filter_name, 0xff & ke->flags,
		    flags_str, 0xffff & ke->fflags, fflags_str, ke->data,
		    ke->udata);
	}

	return (0);
}

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
	error = fmaster_write_payloaded_command(td, CALL_KEVENT, payload);
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
	if (cmd != RET_KEVENT)
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
detect_master_fd(struct thread *td, struct kevent *kchangelist, int nchanges)
{
	struct kevent *kev;
	enum fmaster_fd_type fdtype;
	int error, i;

	for (i = 0; i < nchanges; i++) {
		kev = &kchangelist[i];
		switch (kev->filter) {
		case EVFILT_READ:
		case EVFILT_WRITE:
		case EVFILT_VNODE:
			error = fmaster_type_of_fd(td, kev->ident, &fdtype);
			if (error != 0)
				return (error);
			if (fdtype != FD_SLAVE)
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

static int
fmaster_kevent_main(struct thread *td, struct fmaster_kevent_args *uap)
{
	struct malloc_type *mt;
	struct kevent *kchangelist;
	enum fmaster_fd_type fdtype;
	int error, nchanges;

	nchanges = uap->nchanges;
	mt = M_TEMP;
	error = copyin_changelist(uap->changelist, nchanges, mt, &kchangelist);
	if (error != 0)
		return (error);
	error = log_args(td, uap, kchangelist);
	if (error != 0)
		goto exit;

	/*
	 * This implementation cannot work for the master.
	 */
	error = fmaster_type_of_fd(td, uap->fd, &fdtype);
	if (error != 0)
		goto exit;
	if (fdtype != FD_SLAVE) {
		error = EBADF;
		goto exit;
	}
	error = detect_master_fd(td, kchangelist, nchanges);
	if (error != 0)
		goto exit;

	error = execute_call(td, uap, kchangelist);
	if (error != 0)
		goto exit;
	error = execute_return(td, uap);
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
	struct timeval time_start;
	pid_t pid;
	int error;
	const char *name = "kevent";

	pid = td->td_proc->p_pid;
	log(LOG_DEBUG, "fmaster[%d]: %s: started\n", pid, name);
	microtime(&time_start);

	error = fmaster_kevent_main(td, uap);

	fmaster_log_syscall_end(td, name, &time_start, error);

	return (error);
}

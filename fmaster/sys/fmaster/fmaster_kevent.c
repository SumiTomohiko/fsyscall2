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

	len = 0;
	sep = "";
	for (i = 0; i < ndefs; i++) {
		if ((flags & defs[i].value) == 0)
			continue;
		size = bufsize - len;
		len += snprintf(&buf[len], size, "%s%s", sep, defs[i].name);
		sep = "|";
	}
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
		return;
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

static int
log_args(struct thread *td, struct fmaster_kevent_args *uap)
{
	struct kevent *changelist, *ke;
	pid_t pid;
	unsigned long size;
	int error, flt, i, nchanges;
	const char *filter_name;
	char fflags_str[256], flags_str[256], header[64];

	pid = td->td_proc->p_pid;
	snprintf(header, sizeof(header), "fmaster[%d]: kevent", pid);

	nchanges = uap->nchanges;
	log(LOG_DEBUG,
	    "%s: fd=%d, changelist=%p, nchanges=%d, eventlist=%p, nevents=%d, t"
	    "imeout=%p\n",
	    header, uap->fd, uap->changelist, nchanges, uap->eventlist,
	    uap->nevents, uap->timeout);

	if ((uap->changelist == NULL) || (nchanges == 0))
		return (0);
	size = sizeof(*changelist) * nchanges;
	changelist = (struct kevent *)malloc(size, M_TEMP, M_WAITOK);
	error = copyin(uap->changelist, changelist, size);
	if (error != 0)
		return (error);
	for (i = 0; i < nchanges; i++) {
		ke = &changelist[i];

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
fmaster_kevent_main(struct thread *td, struct fmaster_kevent_args *uap)
{
	int error;

	error = log_args(td, uap);
	if (error != 0)
		return (error);

	return (ENOSYS);
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

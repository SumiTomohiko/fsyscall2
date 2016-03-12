#include <sys/param.h>
#include <sys/syscallsubr.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static const char *name = "close";

static int
nop(struct thread *td, int fd)
{

	return (0);
}

static int
fmaster_close_main(struct thread *td, struct fmaster_close_args *uap)
{
	int (*closef)(struct thread *, int);
	enum fmaster_file_place place;
	int error, fd, lfd, refcount;
	const char *placestr;

	fd = uap->fd;
	error = fmaster_unref_fd(td, fd, &place, &lfd, &refcount);
	if (error != 0)
		return (error);

	placestr = fmaster_str_of_place(place);
	fmaster_log(td, LOG_DEBUG,
		    "%s: fd=%d, place=%s, lfd=%d, refcount=%d",
		    name, fd, placestr, lfd, refcount);
	if (refcount == 0) {
		fmaster_log(td, LOG_DEBUG,
			    "%s: closing fd %d (%s %d)",
			    name, fd, placestr, lfd);
		switch (place) {
		case FFP_MASTER:
			closef = kern_close;
			break;
		case FFP_SLAVE:
			closef = fmaster_execute_close;
			break;
		case FFP_PENDING_SOCKET:
			fmaster_log(td, LOG_INFO,
				    "%s: closed a pending socket: fd=%d",
				    name, fd);
			closef = nop;
			break;
		default:
			return (EINVAL);
		}
		error = closef(td, lfd);
		if (error != 0)
			return (error);
	}

	return (0);
}

int
sys_fmaster_close(struct thread *td, struct fmaster_close_args *uap)
{
	struct timeval time_start;
	int error;

	fmaster_log(td, LOG_DEBUG, "%s: started: fd=%d", name, uap->fd);
	microtime(&time_start);

	error = fmaster_close_main(td, uap);

	fmaster_log_syscall_end(td, name, &time_start, error);

	return (error);
}

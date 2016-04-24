#include <sys/param.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/libkern.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

static const char *sysname = "fcntl";

static int
fmaster_fcntl_main(struct thread *td, int fd, int cmd, long arg)
{
	enum fmaster_file_place place;
	int error, flags, lfd;
	bool b;

	error = fmaster_get_vnode_info(td, fd, &place, &lfd);
	if (error != 0)
		return (error);
	switch (place) {
	case FFP_MASTER:
		return (kern_fcntl(td, lfd, cmd, arg));
	case FFP_SLAVE:
		return (fmaster_execute_fcntl(td, lfd, cmd, arg));
	case FFP_PENDING_SOCKET:
		switch (cmd) {
		case F_SETFD:
			b = (arg & FD_CLOEXEC) != 0 ? true : false;
			return (fmaster_set_close_on_exec(td, fd, b));
		case F_GETFL:
			error = fmaster_get_file_status_flags(td, fd, &flags);
			if (error != 0)
				return (error);
			td->td_retval[0] = flags;
			return (0);
		case F_SETFL:
			return (fmaster_set_file_status_flags(td, fd, arg));
		default:
			return (EOPNOTSUPP);
		}
	default:
		return (EINVAL);
	}
}

static const char *
get_cmd_name(int cmd)
{
	static const char *names[] = {
		"F_DUPFD",
		"F_GETFD",
		"F_SETFD",
		"F_GETFL",
		"F_SETFL",
		"F_GETOWN",
		"F_SETOWN",
		"F_OGETLK",
		"F_OSETLK",
		"F_OSETLKW",
		"F_DUP2FD",
		"F_GETLK",
		"F_SETLK",
		"F_SETLKW",
		"F_SETLK_REMOTE",
		"F_READAHEAD",
		"F_RDAHEAD"
	};
	const char *name;

	name = (0 <= cmd) && (cmd < array_sizeof(names)) ? names[cmd]
							 : "invalid";

	return (name);
}

static void
log_SETFL(struct thread *td, int fd, int cmd, long arg)
{
	static struct flag_definition flags[] = {
		DEFINE_FLAG(O_NONBLOCK),
		DEFINE_FLAG(O_APPEND),
		DEFINE_FLAG(O_DIRECT),
		DEFINE_FLAG(O_ASYNC)
	};
	char buf[1024];

	fmaster_chain_flags(buf, sizeof(buf), arg, flags, array_sizeof(flags));
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: fd=%d, cmd=%d (%s), arg=0x%lx (%s)",
		    sysname, fd, cmd, get_cmd_name(cmd), arg, buf);
}

static void
log_SETFD(struct thread *td, int fd, int cmd, long arg)
{
	static struct flag_definition flags[] = {
		DEFINE_FLAG(FD_CLOEXEC)
	};
	char buf[1024];

	fmaster_chain_flags(buf, sizeof(buf), arg, flags, array_sizeof(flags));
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: fd=%d, cmd=%d (%s), arg=0x%lx (%s)",
		    sysname, fd, cmd, get_cmd_name(cmd), arg, buf);
}

static void
log_get(struct thread *td, int fd, int cmd, long unused)
{

	fmaster_log(td, LOG_DEBUG,
		    "%s: started: fd=%d, cmd=%d (%s)",
		    sysname, fd, cmd, get_cmd_name(cmd));
}

static void
log_default(struct thread *td, int fd, int cmd, long arg)
{

	fmaster_log(td, LOG_DEBUG,
		    "%s: started: fd=%d, cmd=%d (%s), arg=0x%lx",
		    sysname, fd, cmd, get_cmd_name(cmd), arg);
}

int
sys_fmaster_fcntl(struct thread *td, struct fmaster_fcntl_args *uap)
{
	struct timeval time_start;
	long arg;
	int cmd, error, fd;
	void (*log)(struct thread *, int, int, long);

	fd = uap->fd;
	cmd = uap->cmd;
	arg = uap->arg;
	switch (cmd) {
	case F_SETFD:
		log = log_SETFD;
		break;
	case F_SETFL:
		log = log_SETFL;
		break;
	case F_GETFD:
	case F_GETFL:
		log = log_get;
		break;
	default:
		log = log_default;
		break;
	}
	log(td, fd, cmd, arg);
	microtime(&time_start);

	error = fmaster_fcntl_main(td, fd, cmd, arg);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

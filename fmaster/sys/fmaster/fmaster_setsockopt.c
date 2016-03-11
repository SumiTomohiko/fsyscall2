#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/payload.h>
#include <sys/fmaster/fmaster_proto.h>

/*******************************************************************************
 * code for slave
 */

static int
setsockopt_slave(struct thread *td, int lfd, int level, int name, void *val,
		 int valsize)
{
	int error, optval;

	if (valsize != sizeof(optval))
		return (EFAULT);
	error = copyin(val, &optval, valsize);
	if (error != 0)
		return (error);

	error = fmaster_execute_setsockopt(td, lfd, level, name, &optval,
					   valsize);
	if (error != 0)
		return (error);

	return (0);
}

/*******************************************************************************
 * code for master
 */
static int
setsockopt_master(struct thread *td, int lfd, int level, int name, void *val,
		  int valsize)
{
	int error;

	error = kern_setsockopt(td, lfd, level, name, val, UIO_USERSPACE,
				valsize);

	return (error);
}

/*******************************************************************************
 * shared
 */

static int
fmaster_setsockopt_main(struct thread *td, int s, int level, int name, void *val, int valsize)
{
	enum fmaster_file_place place;
	int error, lfd;

	error = fmaster_get_vnode_info(td, s, &place, &lfd);
	if (error != 0)
		return (error);
	switch (place) {
	case FFP_MASTER:
		return (setsockopt_master(td, lfd, level, name, val, valsize));
	case FFP_SLAVE:
		return (setsockopt_slave(td, lfd, level, name, val, valsize));
	case FFP_PENDING_SOCKET:
		error = fmaster_setsockopt_pending_sock(td, s, level, name, val,
							valsize);
		return (error);
	default:
		return (EINVAL);
	}
}

int
sys_fmaster_setsockopt(struct thread *td, struct fmaster_setsockopt_args *uap)
{
	struct timeval time_start;
	int error, level, name, s, valsize;
	const char *sysname = "setsockopt";
	void *val;

	s = uap->s;
	level = uap->level;
	name = uap->name;
	val = uap->val;
	valsize = uap->valsize;
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: s=%d, level=0x%x, name=%d (%s), val=%p, valsi"
		    "ze=%d",
		    sysname, s, level, name, fmaster_get_sockopt_name(name),
		    val, valsize);

	error = fmaster_setsockopt_main(td, s, level, name, val, valsize);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

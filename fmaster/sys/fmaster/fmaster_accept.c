#include <sys/param.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
accept_master(struct thread *td, int s /* local */, struct sockaddr *name,
	      socklen_t *anamelen)
{
	struct sockaddr *addr;
	socklen_t addrlen;
	int error;

	error = kern_accept(td, s, &addr, &addrlen, NULL);
	if (error != 0)
		return (error);
	error = fmaster_copyout_sockaddr(addr, addrlen, name, anamelen);
	if (error != 0)
		goto exit;

	error = 0;
exit:
	free(addr, M_SONAME);

	return (error);
}

static int
accept_main(struct thread *td, int s, struct sockaddr *name,
	    socklen_t *anamelen)
{
	enum fmaster_file_place place;
	int error, fd, lfd;
	char desc[VNODE_DESC_LEN];

	error = fmaster_get_vnode_info(td, s, &place, &lfd);
	if (error != 0)
		return (error);
	switch (place) {
	case FFP_MASTER:
		error = accept_master(td, lfd, name, anamelen);
		break;
	case FFP_SLAVE:
		error = fmaster_execute_accept_protocol(td, ACCEPT_CALL,
							ACCEPT_RETURN, lfd,
							name, anamelen);
		break;
	case FFP_PENDING_SOCKET:
	default:
		return (EINVAL);
	}
	if (error != 0)
		return (error);

	fd = td->td_retval[0];
	snprintf(desc, sizeof(desc), "accept(s=%d)", s);
	error = fmaster_return_fd(td, DTYPE_SOCKET, place, fd, desc);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_accept(struct thread *td, struct fmaster_accept_args *uap)
{
	struct sockaddr *name;
	struct timeval time_start;
	socklen_t *anamelen;
	int error, s;
	const char *fmt = "%s: started: s=%d, name=%p, anamelen=%p";
	const char *sysname = "accept";

	s = uap->s;
	name = uap->name;
	anamelen = uap->anamelen;
	fmaster_log(td, LOG_DEBUG, fmt, sysname, s, name, anamelen);
	microtime(&time_start);

	error = accept_main(td, s, name, anamelen);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

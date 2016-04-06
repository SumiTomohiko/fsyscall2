#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

/*
 * This code is almost same as fmaster_getsockname.c.
 */

static int
getpeername_master(struct thread *td, int s /* local */, struct sockaddr *name,
		   socklen_t *namelen)
{
	struct sockaddr *addr;
	socklen_t addrlen;
	int error;

	error = kern_getpeername(td, s, &addr, &addrlen);
	if (error != 0)
		return (error);
	error = fmaster_copyout_sockaddr(addr, addrlen, name, namelen);
	if (error != 0)
		goto exit;

	error = 0;
exit:
	free(addr, M_SONAME);

	return (error);
}

static int
getpeername_main(struct thread *td, int s, struct sockaddr *name,
		 socklen_t *namelen)
{
	enum fmaster_file_place place;
	int error, lfd;

	error = fmaster_get_vnode_info(td, s, &place, &lfd);
	if (error != 0)
		return (error);
	switch (place) {
	case FFP_MASTER:
		error = getpeername_master(td, lfd, name, namelen);
		break;
	case FFP_SLAVE:
		error = fmaster_execute_accept_protocol(td, GETPEERNAME_CALL,
							GETPEERNAME_RETURN, lfd,
							name, namelen);
		break;
	case FFP_PENDING_SOCKET:
	default:
		return (EINVAL);
	}
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_getpeername(struct thread *td, struct fmaster_getpeername_args *uap)
{
	struct sockaddr *asa;
	struct timeval time_start;
	socklen_t *alen;
	int error, fdes;
	const char *fmt = "%s: started: fdes=%d, asa=%p, alen=%p";
	const char *sysname = "getpeername";

	fdes = uap->fdes;
	asa = uap->asa;
	alen = uap->alen;
	fmaster_log(td, LOG_DEBUG, fmt, sysname, fdes, asa, alen);
	microtime(&time_start);

	error = getpeername_main(td, fdes, asa, alen);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

/*
 * This code is almost same as fmaster_getpeername.c.
 */

static int
getsockname_master(struct thread *td, int s /* local */, struct sockaddr *name,
		   socklen_t *namelen)
{
	struct sockaddr *addr;
	socklen_t addrlen;
	int error;

	error = kern_getsockname(td, s, &addr, &addrlen);
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
getsockname_main(struct thread *td, int s, struct sockaddr *name,
		 socklen_t *namelen)
{
	enum fmaster_file_place place;
	int error, lfd;

	error = fmaster_get_vnode_info(td, s, &place, &lfd);
	if (error != 0)
		return (error);
	switch (place) {
	case FFP_MASTER:
		error = getsockname_master(td, lfd, name, namelen);
		break;
	case FFP_SLAVE:
		error = fmaster_execute_accept_protocol(td, GETSOCKNAME_CALL,
							GETSOCKNAME_RETURN, lfd,
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
sys_fmaster_getsockname(struct thread *td, struct fmaster_getsockname_args *uap)
{
	struct sockaddr *asa;
	struct timeval time_start;
	socklen_t *alen;
	int error, fdes;
	const char *fmt = "%s: started: fdes=%d, asa=%p, alen=%p";
	const char *sysname = "getsockname";

	fdes = uap->fdes;
	asa = uap->asa;
	alen = uap->alen;
	fmaster_log(td, LOG_DEBUG, fmt, sysname, fdes, asa, alen);
	microtime(&time_start);

	error = getsockname_main(td, fdes, asa, alen);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

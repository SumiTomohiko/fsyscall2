#include <sys/param.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

/*******************************************************************************
 * shared code
 */

static const char *sysname = "accept4";

/*******************************************************************************
 * code for master
 */

static int
accept4_master(struct thread *td, int s /* local */, struct sockaddr *name,
	       socklen_t *anamelen, int flags)
{
	struct sockaddr *addr;
	socklen_t addrlen;
	int error;

	if ((name == NULL) || (anamelen == NULL))
		return (kern_accept4(td, s, NULL, NULL, flags, NULL));

	error = copyin(anamelen, &addrlen, sizeof(addrlen));
	if (error != 0)
		return (error);
	error = kern_accept4(td, s, &addr, &addrlen, flags, NULL);
	if (error != 0)
		return (error);
	error = copyout(&addrlen, anamelen, sizeof(addrlen));
	if (error != 0)
		goto exit;

	error = 0;
exit:
	free(addr, M_SONAME);

	return (error);
}

/*******************************************************************************
 * code for slave
 */

static int
execute_call(struct thread *td, int s /* local */, socklen_t namelen, int flags)
{
	struct payload *payload;
	int error;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);

	error = fsyscall_payload_add_int(payload, s);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_socklen(payload, namelen);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_int(payload, flags);
	if (error != 0)
		goto exit;

	error = fmaster_write_payloaded_command(td, ACCEPT4_CALL, payload);
	if (error != 0)
		goto exit;

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
accept4_slave(struct thread *td, int s /* local */, struct sockaddr *name,
	      socklen_t *anamelen, int flags)
{
	int error;

	error = execute_call(td, s, sizeof(struct sockaddr_storage), flags);
	if (error != 0)
		return (error);
	error = fmaster_execute_accept_return(td, ACCEPT4_RETURN, name,
					      anamelen);
	if (error != 0)
		return (error);

	return (0);
}

/*******************************************************************************
 * entry point
 */

static int
accept4_main(struct thread *td, int s, struct sockaddr *name,
	     socklen_t *anamelen, int flags)
{
	enum fmaster_file_place place;
	int error, f, fd, lfd;
	char desc[VNODE_DESC_LEN];

	error = fmaster_get_vnode_info(td, s, &place, &lfd);
	if (error != 0)
		return (error);
	f = ~SOCK_CLOEXEC & flags;
	switch (place) {
	case FFP_MASTER:
		error = accept4_master(td, lfd, name, anamelen, f);
		break;
	case FFP_SLAVE:
		error = accept4_slave(td, lfd, name, anamelen, f);
		break;
	case FFP_PENDING_SOCKET:
	default:
		return (EINVAL);
	}
	if (error != 0)
		return (error);

	fd = td->td_retval[0];
	snprintf(desc, sizeof(desc), "%s(s=%d)", sysname, s);
	error = fmaster_return_fd(td, DTYPE_SOCKET, place, fd, desc);
	if (error != 0)
		return (error);
	/* fmaster_return_fd() overwrote td->td_retval[0] with the virtual fd */
	error = fmaster_set_close_on_exec(td, td->td_retval[0],
					  (SOCK_CLOEXEC & flags) != 0);
	if (error != 0)
		return (error);

	return (0);
}

static struct flag_definition flag_defs[] = {
	DEFINE_FLAG(SOCK_CLOEXEC),
	DEFINE_FLAG(SOCK_NONBLOCK)
};

int
sys_fmaster_accept4(struct thread *td, struct fmaster_accept4_args *uap)
{
	struct sockaddr *name;
	struct timeval time_start;
	socklen_t *anamelen;
	int error, flags, s;
	const char *fmt = "%s: started: s=%d, name=%p, anamelen=%p, flags=0x%x "
			  "(%s)";
	char buf[256];

	s = uap->s;
	name = uap->name;
	anamelen = uap->anamelen;
	flags = uap->flags;
	fmaster_chain_flags(buf, sizeof(buf), flags, flag_defs,
			    array_sizeof(flag_defs));
	fmaster_log(td, LOG_DEBUG, fmt, sysname, s, name, anamelen, flags, buf);
	microtime(&time_start);

	error = accept4_main(td, s, name, anamelen, flags);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/un.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
bind_main(struct thread *td, int s, struct sockaddr *name, socklen_t namelen)
{
	struct sockaddr_storage buf;
	const struct sockaddr *addr;
	int error;
	char desc[VNODE_DESC_LEN];

	error = copyin(name, &buf, namelen);
	if (error != 0)
		return (error);
	addr = (const struct sockaddr *)&buf;
	switch (addr->sa_family) {
	case AF_LOCAL:
		snprintf(desc, sizeof(desc),
			 "bound on %s",
			 ((const struct sockaddr_un *)addr)->sun_path);
		break;
	default:
		strcpy(desc, "bound");
		break;
	}

	error = fmaster_fix_pending_socket_to_slave(td, s, desc);
	if (error != 0)
		return (error);

	error = fmaster_execute_connect_protocol(td, BIND_CALL, BIND_RETURN, s,
						 name, namelen);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_bind(struct thread *td, struct fmaster_bind_args *uap)
{
	struct sockaddr *name;
	struct timeval time_start;
	socklen_t namelen;
	int error, s;
	const char *fmt = "%s: started: s=%d, name=%p, namelen=%d";
	const char *sysname = "bind";

	s = uap->s;
	name = (struct sockaddr *)uap->name;
	namelen = uap->namelen;
	fmaster_log(td, LOG_DEBUG, fmt, sysname, s, name, namelen);
	microtime(&time_start);

	error = bind_main(td, s, name, namelen);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

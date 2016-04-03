#include <sys/param.h>
#include <sys/proc.h>
#include <sys/un.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
bind_main(struct thread *td, int s, struct sockaddr *name, socklen_t namelen)
{
	int error;

	error = fmaster_fix_pending_socket_to_slave(td, s, "bound");
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

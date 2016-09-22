#include <sys/types.h>
#include <sys/libkern.h>
#include <sys/sysproto.h>
#include <sys/un.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

/*******************************************************************************
 * code for slave
 */

static int
connect_slave(struct thread *td, int s, struct sockaddr *uname,
	      socklen_t namelen, const char *desc)
{
	int error;

	error = fmaster_fix_pending_socket_to_slave(td, s, desc);
	if (error != 0)
		return (error);
	error = fmaster_execute_connect_protocol(td, CONNECT_CALL,
						 CONNECT_RETURN, s, uname,
						 namelen);
	if (error != 0)
		return (error);

	return (0);
}

/*******************************************************************************
 * code for master
 */

static int
connect_master(struct thread *td, int s, struct sockaddr *uname,
	       socklen_t namelen, const char *desc)
{
	struct connect_args args;
	int error, fd;

	error = fmaster_fix_pending_socket_to_master(td, s, desc);
	if (error != 0)
		return (error);

	error = fmaster_get_vnode_info(td, s, NULL, &fd);
	if (error != 0)
		return (error);
	args.s = fd;
	args.name = (caddr_t)uname;
	args.namelen = namelen;
	error = sys_connect(td, &args);
	if (error != 0)
		return (error);

	return (0);
}

/*******************************************************************************
 * shared code
 */

static bool
is_master_addr(struct sockaddr *kname)
{
	struct sockaddr_un *addr;

	if (kname->sa_family != AF_LOCAL)
		return (false);
	addr = (struct sockaddr_un *)kname;
	if (strcmp(addr->sun_path,
		   "/home/tom/.local/var/run/dbus/system_bus_socket") != 0)
		return (false);

	return (true);
}

static int
connect_main(struct thread *td, int s, struct sockaddr *uname,
	     socklen_t namelen)
{
	struct sockaddr_storage addr;
	struct sockaddr *paddr;
	int error;
	char desc[8192];
	int (*f)(struct thread *, int, struct sockaddr *, socklen_t,
		 const char *);

	paddr = (struct sockaddr *)&addr;
	error = copyin(uname, paddr, MIN(sizeof(addr), namelen));
	if (error != 0)
		return (error);
	switch (paddr->sa_family) {
	case AF_LOCAL:
		snprintf(desc, sizeof(desc),
			 "connected to %s",
			 ((struct sockaddr_un *)paddr)->sun_path);
		break;
	default:
		strcpy(desc, "connected");
		break;
	}

	f = is_master_addr(paddr) ? connect_master : connect_slave;
	error = f(td, s, uname, namelen, desc);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_connect(struct thread *td, struct fmaster_connect_args *uap)
{
	struct sockaddr *name;
	struct timeval time_start;
	socklen_t namelen;
	int error, s;
	const char *fmt = "%s: started: s=%d, name=%p, namelen=%d";
	const char *sysname = "connect";

	s = uap->s;
	name = (struct sockaddr *)uap->name;
	namelen = uap->namelen;
	fmaster_log(td, LOG_DEBUG, fmt, sysname, s, name, namelen);
	microtime(&time_start);

	error = connect_main(td, s, name, namelen);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

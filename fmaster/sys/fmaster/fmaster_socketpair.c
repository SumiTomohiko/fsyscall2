#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
fmaster_socketpair_main(struct thread *td, struct fmaster_socketpair_args *uap)
{
	int error, i, rsv[2], sv[2], vfd;
	char desc[VNODE_DESC_LEN];

	error = kern_socketpair(td, uap->domain, uap->type, uap->protocol, rsv);
	if (error != 0)
		return (error);
	snprintf(desc, sizeof(desc), "socketpair (%d, %d)", rsv[0], rsv[1]);
	for (i = 0; i < sizeof(rsv) / sizeof(rsv[0]); i++) {
		error = fmaster_register_file(td, FFP_MASTER, rsv[i], &vfd,
					      desc);
		if (error != 0)
			return (error);
		sv[i] = vfd;
	}
	error = copyout(sv, uap->rsv, sizeof(sv));
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_socketpair(struct thread *td, struct fmaster_socketpair_args *uap)
{
	struct timeval time_start;
	int error;
	const char *name = "socketpair";

	fmaster_log(td, LOG_DEBUG, "%s: started", name);
	microtime(&time_start);

	error = fmaster_socketpair_main(td, uap);

	fmaster_log_syscall_end(td, name, &time_start, error);

	return (error);
}

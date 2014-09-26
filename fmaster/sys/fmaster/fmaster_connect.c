#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_connect(struct thread *td, struct fmaster_connect_args *uap)
{
	int error;

	error = fmaster_execute_connect_protocol(td, "connect", CALL_CONNECT,
						 RET_CONNECT, uap->s,
						 (struct sockaddr *)uap->name,
						 uap->namelen);

	return (error);
}

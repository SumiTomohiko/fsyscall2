#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_getpeername(struct thread *td, struct fmaster_getpeername_args *uap)
{
	int error;

	error = fmaster_execute_getsockname_protocol(td, "getpeername",
						     CALL_GETPEERNAME,
						     RET_GETPEERNAME, uap->fdes,
						     uap->asa, uap->alen);

	return (error);
}

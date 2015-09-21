#include <sys/param.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_accept(struct thread *td, struct fmaster_accept_args *uap)
{
	int error;
	char desc[VNODE_DESC_LEN];

	error = fmaster_execute_accept_protocol(td, "accept", ACCEPT_CALL,
						ACCEPT_RETURN, uap->s,
						uap->name, uap->anamelen);
	if (error != 0)
		return (error);
	snprintf(desc, sizeof(desc), "accept(s=%d)", uap->s);
	error = fmaster_return_fd(td, FFP_SLAVE, td->td_retval[0], desc);
	if (error != 0)
		return (error);

	return (0);
}
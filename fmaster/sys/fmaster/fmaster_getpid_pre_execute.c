#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

enum fmaster_pre_execute_result
fmaster_getpid_pre_execute(struct thread *td, struct fmaster_getpid_args *uap,
			   int *error)
{
	pid_t slave_pid;

	slave_pid = fmaster_get_slave_pid(td);
	if (slave_pid == SLAVE_PID_UNKNOWN)
		return (PRE_EXEC_CONT);

	td->td_retval[0] = slave_pid;
	*error = 0;

	return (PRE_EXEC_END);
}

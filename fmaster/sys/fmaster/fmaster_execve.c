#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_execve(struct thread *td, struct fmaster_execve_args *uap)
{
	pid_t pid;
	int error;
	char path[MAXPATHLEN];

	error = copyin(uap->fname, path, sizeof(path));
	if (error != 0)
		return (error);
	pid = td->td_proc->p_pid;
	log(LOG_DEBUG, "fmaster[%d]: execve: started: path=%s", pid, path);

	error = sys_execve(td, (struct execve_args *)uap);

	return (error);
}

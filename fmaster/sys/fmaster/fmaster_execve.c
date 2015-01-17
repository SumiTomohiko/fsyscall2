#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <sys/fmaster/fmaster_proto.h>

static int
log_array(struct thread *td, char **p, const char *name)
{
	pid_t pid;
	int error, i;
	const char *fmt = "fmaster[%d]: execve: %s[%d]=%s\n";
	const char *fmt2 = "fmaster[%d]: execve: number of %s is %d\n";
	char buf[1024];

	pid = td->td_proc->p_pid;
	if (p == NULL) {
		log(LOG_DEBUG, "fmaster[%d]: execve: %s=NULL\n", pid, name);
		return (0);
	}

	for (i = 0; p[i] != NULL; i++) {
		error = copyinstr(p[i], buf, sizeof(buf), NULL);
		if (error != 0)
			return (error);
		log(LOG_DEBUG, fmt, pid, name, i, buf);
	}
	log(LOG_DEBUG, fmt2, pid, name, i);

	return (0);
}

int
sys_fmaster_execve(struct thread *td, struct fmaster_execve_args *uap)
{
	pid_t pid;
	int error;
	char path[MAXPATHLEN];

	error = copyinstr(uap->fname, path, sizeof(path), NULL);
	if (error != 0)
		return (error);
	pid = td->td_proc->p_pid;
	log(LOG_DEBUG, "fmaster[%d]: execve: started: path=%s\n", pid, path);
	error = log_array(td, uap->argv, "argv");
	if (error != 0)
		return (error);
	error = log_array(td, uap->envv, "envv");
	if (error != 0)
		return (error);

	error = sys_execve(td, (struct execve_args *)uap);

	return (error);
}

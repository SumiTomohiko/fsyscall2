#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
log_array(struct thread *td, char **p, const char *name)
{
	int error, i;
	char buf[1024];

	if (p == NULL) {
		fmaster_log(td, LOG_DEBUG, "execve: %s=NULL", name);
		return (0);
	}

	for (i = 0; p[i] != NULL; i++) {
		error = copyinstr(p[i], buf, sizeof(buf), NULL);
		if (error != 0)
			return (error);
		fmaster_log(td, LOG_DEBUG, "execve: %s[%d]=%s", name, i, buf);
	}
	fmaster_log(td, LOG_DEBUG, "execve: number of %s is %d", name, i);

	return (0);
}

static int
execve_main(struct thread *td, struct fmaster_execve_args *uap)
{
	int error;

	error = fmaster_close_on_exec(td);
	if (error != 0)
		return (error);
	error = sys_execve(td, (struct execve_args *)uap);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_execve(struct thread *td, struct fmaster_execve_args *uap)
{
	struct timeval time_start;
	int error;
	const char *sysname = "execve";
	char path[MAXPATHLEN];

	error = copyinstr(uap->fname, path, sizeof(path), NULL);
	if (error != 0)
		return (error);
	fmaster_log(td, LOG_DEBUG, "%s: started: path=%s", sysname, path);
	error = log_array(td, uap->argv, "argv");
	if (error != 0)
		return (error);
	error = log_array(td, uap->envv, "envv");
	if (error != 0)
		return (error);
	microtime(&time_start);

	error = execve_main(td, uap);

	switch (error) {
	case 0:
	case EACCES:
	case ENAMETOOLONG:
	case ENOENT:
	case ENOEXEC:
		break;
	default:
		fmaster_log(td, LOG_CRIT, "cannot execve(2)");
		break;
	}

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

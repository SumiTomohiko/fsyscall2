#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
getdirentries_main(struct thread *td, int fd, char *ubuf, unsigned int count,
		   long *ubasep)
{
	long base;
	int error;

	error = fmaster_execute_getdirentries(td, fd, ubuf, count, &base);
	if (error != 0)
		return (error);
	if (ubasep != NULL) {
		error = copyout(&base, ubasep, sizeof(base));
		if (error != 0)
			return (error);
	}

	return (0);
}

int
sys_fmaster_getdirentries(struct thread *td,
			  struct fmaster_getdirentries_args *uap)
{
	struct timeval t;
	long *basep;
	unsigned int count;
	int error, fd;
	const char *sysname = "getdirentries";
	char *buf;

	fd = uap->fd;
	buf = uap->buf;
	count = uap->count;
	basep = uap->basep;
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: fd=%d, buf=%p, count=%u, basep=%p",
		    sysname, fd, buf, count, basep);
	microtime(&t);

	error = getdirentries_main(td, fd, buf, count, basep);

	fmaster_log_syscall_end(td, sysname, &t, error);

	return (error);
}

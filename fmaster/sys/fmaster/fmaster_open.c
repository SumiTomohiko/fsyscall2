#include <sys/param.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/libkern.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_open(struct thread *td, struct fmaster_open_args *uap)
{
	struct timeval time_start;
	int error, flags;
	mode_t mode;
	const char *sysname = "open";
	char path[MAXPATHLEN];

	error = copyinstr(uap->path, path, sizeof(path), NULL);
	if (error != 0) {
		fmaster_log(td, LOG_ERR,
			    "%s: cannot copyinstr path: error=%d",
			    sysname, error);
		return (error);
	}
	flags = uap->flags;
	mode = uap->mode;
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: path=\"%s\", flags=0x%x, mode=0o%o",
		    sysname, path, flags, mode);
	microtime(&time_start);

	error = fmaster_open(td, sysname, path, flags, mode);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

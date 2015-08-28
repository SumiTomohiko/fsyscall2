#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_sendto(struct thread *td, struct fmaster_sendto_args *uap)
{
	struct fmaster_write_args args;
	int error;

	args.fd = uap->s;
	args.buf = uap->buf;
	args.nbytes = uap->len;

	error = sys_fmaster_write(td, &args);

	return (error);
}

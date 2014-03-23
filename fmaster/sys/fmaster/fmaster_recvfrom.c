#include <sys/fmaster/fmaster_proto.h>

int
sys_fmaster_recvfrom(struct thread *td, struct fmaster_recvfrom_args *uap)
{
	struct fmaster_read_args args;

	if ((uap->flags != 0) || (uap->from != NULL) || (uap->fromlenaddr != 0))
		return (ENOSYS);
	args.fd = uap->s;
	args.buf = uap->buf;
	args.nbytes = uap->len;
	return (sys_fmaster_read(td, &args));
}

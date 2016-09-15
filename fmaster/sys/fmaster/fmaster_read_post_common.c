#include <sys/param.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

int
fmaster_read_post_common(struct thread *td, struct fmaster_read_args *uap)
{
	struct malloc_type *mt;
	size_t nbytes;
	int error, fd;
	char *buf, tag[256];

	mt = M_TEMP;
	nbytes = td->td_retval[0];
	buf = (char *)malloc(nbytes, mt, M_WAITOK);
	if (buf == NULL)
		return (ENOMEM);
	error = copyin(uap->buf, buf, nbytes);
	if (error != 0)
		goto exit;

	fd = uap->fd;
#if 0
	snprintf(tag, sizeof(tag), "read(2) from fd %d", fd);
	fmaster_log_all(td, tag, buf, nbytes);
#endif
	snprintf(tag, sizeof(tag), "read: fd=%d: buf", fd);
	fmaster_log_buf(td, tag, buf, nbytes);

	error = 0;
exit:
	free(buf, mt);

	return (error);
}

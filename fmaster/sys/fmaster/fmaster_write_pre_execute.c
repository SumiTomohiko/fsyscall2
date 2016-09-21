#include <sys/param.h>
#include <sys/types.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

/**
 * Sometimes a message to fd 2 is an important dying message. So the write(2)
 * logs it.
 */
enum fmaster_pre_execute_result
fmaster_write_pre_execute(struct thread *td, struct fmaster_write_args *uap,
			  int *error)
{
	struct malloc_type *mt;
	size_t nbytes;
	int fd;
	char *buf, tag[256];

	nbytes = uap->nbytes;

	mt = M_TEMP;
	buf = (char *)malloc(nbytes, mt, M_WAITOK);
	if (buf == NULL)
		goto exit;
	*error = copyin(uap->buf, buf, nbytes);
	if (*error != 0)
		goto exit2;

	fd = uap->fd;
	switch (fd) {
	case 1:
	case 2:
#if 0
		snprintf(tag, sizeof(tag), "write(2) to fd %d", fd);
		fmaster_log_all(td, tag, buf, nbytes);
#endif
		/* FALLTHROUGH */
	default:
		snprintf(tag, sizeof(tag), "write: fd=%d: buf", fd);
		fmaster_log_buf(td, tag, buf, nbytes);
		break;
	}

exit2:
	free(buf, mt);

exit:
	return (PRE_EXEC_CONT);
}

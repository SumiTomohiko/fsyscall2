#include <sys/param.h>
#include <sys/types.h>
#include <sys/libkern.h>
#include <sys/malloc.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

static void
log_error(struct thread *td, int fd, const char *buf, size_t nbytes)
{
	static char chars[] = {
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', '!', '"', '#', '$', '%', '&', '\'',
		'(', ')', '*', '+', ',', '-', '.', '/',
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', ':', ';', '<', '=', '>', '?',
		'@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
		'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
		'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
		'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
		'`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
		'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
		'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
		'x', 'y', 'z', '{', '|', '}', '~', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '
	};
	size_t size;
	pid_t pid;
	int i;
	const char *fmt = "write(2) to fd 2: buf[%d]=0x%02x (%c)";
	unsigned char c;

	if (fd != 2)
		return;
	pid = td->td_proc->p_pid;
	size = MIN(nbytes, 1024);
	for (i = 0; i < size; i++) {
		c = (unsigned char)buf[i];
		fmaster_log(td, LOG_DEBUG, fmt, i, c, chars[c]);
	}
}

static int
log_buf(struct thread *td, int fd, const char *buf, size_t nbytes)
{
	static char chars[] = {
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		' ', '!', '"', '#', '$', '%', '&', '\'',
		'(', ')', '*', '+', ',', '-', '.', '/',
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', ':', ';', '<', '=', '>', '?',
		'@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
		'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
		'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
		'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
		'`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
		'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
		'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
		'x', 'y', 'z', '{', '|', '}', '~', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?'
	};
	struct malloc_type *mt;
	size_t i, n, size;
	int error;
	unsigned char *p, *q, s[256], *tmp;

	mt = M_TEMP;
	size = MIN(nbytes + 1, sizeof(s));
	tmp = (unsigned char *)malloc(size, mt, M_WAITOK);
	if (tmp == NULL)
		return (ENOMEM);
	n = size - 1;
	error = copyin(buf, tmp, n);
	if (error != 0)
		goto exit;

	for (i = 0, p = &tmp[0], q = &s[0]; i < n; i++, p++, q++)
		*q = chars[(unsigned int)*p];
	*q = '\0';

	fmaster_log(td, LOG_DEBUG, "write: buf: %s", s);

	error = 0;
exit:
	free(tmp, mt);

	return (error);
}

/**
 * Sometimes a message to fd 2 is an important dying message. So the write(2)
 * logs it.
 */
enum fmaster_pre_execute_result
fmaster_write_pre_execute(struct thread *td, struct fmaster_write_args *uap, int *error)
{
	size_t nbytes;
	int fd;
	const char *buf;

	fd = uap->fd;
	buf = uap->buf;
	nbytes = uap->nbytes;

	switch (fd) {
	case 2:
		log_error(td, fd, buf, nbytes);
		break;
	default:
		log_buf(td, fd, buf, nbytes);
		break;
	}

	return (PRE_EXEC_CONT);
}

#include <sys/malloc.h>
#include <sys/select.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/select.h>
#include <sys/fmaster/fmaster_proto.h>

MALLOC_DECLARE(M_TMP);

static int
encode_fds(struct thread *td, int nfds, struct fd_set *fds, char *buf, size_t buf_len)
{
	int fd, i, len, rest;
	char *p;

	p = buf;
	rest = buf_len;
	for (i = 0; i < nfds; i++) {
		if (!FD_ISSET(i, fds))
			continue;
		fd = fmaster_fds_of_thread(td)[i].fd_local;
		len = fsyscall_encode_int32(fd, p, rest);
		if (len == -1)
			return (ENOMEM);
		p += len;
		rest -= len;
	}

	return (0);
}

static int
has_nonslave_fd(struct thread *td, int nfds, struct fd_set *fds)
{
	int i;

	for (i = 0; i < nfds; i++) {
		if (!FD_ISSET(i, fds))
			continue;
		if (fmaster_fds_of_thread(td)[i].fd_type != FD_SLAVE)
			return (1);
	}

	return (0);
}

int
sys_fmaster_select(struct thread *td, struct fmaster_select_args *uap)
{
	struct malloc_type *type;
	struct fd_set exceptfds, readfds, writefds;
	struct timeval *timeout;
	payload_size_t payload_size;
	unsigned long exceptfds_buf_len, readfds_buf_len, writefds_buf_len;
	int e, exceptfds_len, flags, nexceptfds, nexceptfds_len, nfds;
	int nfds_len, nreadfds, nreadfds_len, nwritefds, nwritefds_len;
	int readfds_len, sec_len, timeout_len, usec_len, wfd, writefds_len;
	char *exceptfds_buf, nexceptfds_buf[FSYSCALL_BUFSIZE_INT32];
	char nfds_buf[FSYSCALL_BUFSIZE_INT32];
	char nreadfds_buf[FSYSCALL_BUFSIZE_INT32];
	char nwritefds_buf[FSYSCALL_BUFSIZE_INT32];
	char *readfds_buf, sec_buf[FSYSCALL_BUFSIZE_INT64];
	char timeout_buf[FSYSCALL_BUFSIZE_INT32];
	char usec_buf[FSYSCALL_BUFSIZE_INT64], *writefds_buf;

	nfds = uap->nd;

#define	COPYIN(u, k)	do {				\
	if ((e = copyin((u), (k), sizeof(*k))) != 0)	\
		return (e);				\
} while (0)
	COPYIN(uap->in, &readfds);
	COPYIN(uap->ou, &writefds);
	COPYIN(uap->ex, &exceptfds);
#undef	COPYIN

	if (has_nonslave_fd(td, nfds, &readfds))
		return (EBADF);
	if (has_nonslave_fd(td, nfds, &writefds))
		return (EBADF);
	if (has_nonslave_fd(td, nfds, &exceptfds))
		return (EBADF);
	nreadfds = fsyscall_count_fds(nfds, &readfds);
	nwritefds = fsyscall_count_fds(nfds, &writefds);
	nexceptfds = fsyscall_count_fds(nfds, &exceptfds);

	e = 0;
	writefds_buf = exceptfds_buf = NULL;
	type = M_TMP;
	flags = M_WAITOK;
	readfds_buf_len = nreadfds * FSYSCALL_BUFSIZE_INT32;
	readfds_buf = (char *)malloc(readfds_buf_len, type, flags);
	if (readfds_buf == NULL)
		return (ENOMEM);
	writefds_buf_len = nwritefds * FSYSCALL_BUFSIZE_INT32;
	writefds_buf = (char *)malloc(writefds_buf_len, type, flags);
	if (writefds_buf == NULL) {
		e = ENOMEM;
		goto finally;
	}
	exceptfds_buf_len = nexceptfds * FSYSCALL_BUFSIZE_INT32;
	exceptfds_buf = (char *)malloc(exceptfds_buf_len, type, flags);
	if (exceptfds_buf == NULL) {
		e = ENOMEM;
		goto finally;
	}

	timeout = uap->tv;
#define	ENCODE_INT32(n, buf, len)	do {			\
	len = fsyscall_encode_int32((n), (buf), sizeof(buf));	\
	if (len == -1) {					\
		e = ENOMEM;					\
		goto finally;					\
	}							\
} while (0)
	ENCODE_INT32(nfds, nfds_buf, nfds_len);
	ENCODE_INT32(nreadfds, nreadfds_buf, nreadfds_len);
	ENCODE_INT32(nwritefds, nwritefds_buf, nwritefds_len);
	ENCODE_INT32(nexceptfds, nexceptfds_buf, nexceptfds_len);
	ENCODE_INT32(timeout != NULL ? 1 : 0, timeout_buf, timeout_len);
#undef	ENCODE_INT32
#define	ENCODE_FDS(fds, buf, buf_len, len)	do {		\
	len = encode_fds(td, nfds, &(fds), (buf), (buf_len));	\
	if (len == -1) {					\
		e = ENOMEM;					\
		goto finally;					\
	}							\
} while (0)
	ENCODE_FDS(readfds, readfds_buf, readfds_buf_len, readfds_len);
	ENCODE_FDS(writefds, writefds_buf, writefds_buf_len, writefds_len);
	ENCODE_FDS(exceptfds, exceptfds_buf, exceptfds_buf_len, exceptfds_len);
#undef	ENCODE_FDS
#define	ENCODE_INT64(n, buf, len) do {				\
	len = fsyscall_encode_int64((n), (buf), sizeof(buf));	\
	if (len == -1) {					\
		e = ENOMEM;					\
		goto finally;					\
	}							\
} while (0)
	if (timeout != NULL) {
		ENCODE_INT64(timeout->tv_sec, sec_buf, sec_len);
		ENCODE_INT64(timeout->tv_usec, usec_buf, usec_len);
	}
	else {
		sec_len = usec_len = 0;
	}
#undef	ENCODE_INT64

	payload_size = nfds_len + nreadfds_len + readfds_len + nwritefds_len +
		       writefds_len + nexceptfds_len + exceptfds_len +
		       timeout_len + sec_len + usec_len;
	e = fmaster_write_command(td, CALL_SELECT);
	if (e != 0)
		goto finally;
	e = fmaster_write_payload_size(td, payload_size);
	if (e != 0)
		goto finally;
	wfd = fmaster_wfd_of_thread(td);
#define	WRITE(buf, len)	do {				\
	e = fmaster_write(td, wfd, (buf), (len));	\
	if (e != 0)					\
		goto finally;				\
} while (0)
	WRITE(nfds_buf, nfds_len);
	WRITE(nreadfds_buf, nreadfds_len);
	WRITE(readfds_buf, readfds_len);
	WRITE(nwritefds_buf, nwritefds_len);
	WRITE(writefds_buf, writefds_len);
	WRITE(nexceptfds_buf, nexceptfds_len);
	WRITE(exceptfds_buf, exceptfds_len);
	WRITE(timeout_buf, timeout_len);
	WRITE(sec_buf, sec_len);
	WRITE(usec_buf, usec_len);
#undef	WRITE

finally:
	free(exceptfds_buf, type);
	free(writefds_buf, type);
	free(readfds_buf, type);

	return (e);
}

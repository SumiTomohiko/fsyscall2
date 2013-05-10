#include <sys/malloc.h>
#include <sys/select.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/select.h>
#include <sys/fmaster/fmaster_proto.h>

static int
encode_fds(struct thread *td, int nfds, struct fd_set *fds, char *buf, size_t bufsize, payload_size_t *data_len)
{
	size_t pos;
	int fd, i, len;

	pos = 0;
	for (i = 0; i < nfds; i++) {
		if (!FD_ISSET(i, fds))
			continue;
		fd = fmaster_fds_of_thread(td)[i].fd_local;
		len = fsyscall_encode_int32(fd, buf + pos, bufsize - pos);
		if (len == -1)
			return (ENOMEM);
		pos += len;
	}

	*data_len = pos;

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

static int
write_call(struct thread *td, int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
	struct malloc_type *type;
	payload_size_t exceptfds_len, payload_size, readfds_len, writefds_len;
	unsigned long exceptfds_buf_len, readfds_buf_len, writefds_buf_len;
	int error, flags, nexceptfds, nexceptfds_len, nfds_len, nreadfds;
	int nreadfds_len, nwritefds, nwritefds_len, sec_len, timeout_len;
	int usec_len, wfd;
	char *exceptfds_buf, nexceptfds_buf[FSYSCALL_BUFSIZE_INT32];
	char nfds_buf[FSYSCALL_BUFSIZE_INT32];
	char nreadfds_buf[FSYSCALL_BUFSIZE_INT32];
	char nwritefds_buf[FSYSCALL_BUFSIZE_INT32];
	char *readfds_buf, sec_buf[FSYSCALL_BUFSIZE_INT64];
	char timeout_buf[FSYSCALL_BUFSIZE_INT32];
	char usec_buf[FSYSCALL_BUFSIZE_INT64], *writefds_buf;

	KASSERT(readfds != NULL, "readfds must be NULL.");
	KASSERT(writefds != NULL, "writefds must be NULL.");
	KASSERT(exceptfds != NULL, "exceptfds must be NULL.");

	nreadfds = fsyscall_count_fds(nfds, readfds);
	nwritefds = fsyscall_count_fds(nfds, writefds);
	nexceptfds = fsyscall_count_fds(nfds, exceptfds);

	error = 0;
	writefds_buf = exceptfds_buf = NULL;
	type = M_FMASTER;
	flags = M_WAITOK;
	readfds_buf_len = fsyscall_compute_fds_bufsize(nreadfds);
	readfds_buf = (char *)malloc(readfds_buf_len, type, flags);
	if (readfds_buf == NULL)
		return (ENOMEM);
	writefds_buf_len = fsyscall_compute_fds_bufsize(nwritefds);
	writefds_buf = (char *)malloc(writefds_buf_len, type, flags);
	if (writefds_buf == NULL) {
		error = ENOMEM;
		goto finally;
	}
	exceptfds_buf_len = fsyscall_compute_fds_bufsize(nexceptfds);
	exceptfds_buf = (char *)malloc(exceptfds_buf_len, type, flags);
	if (exceptfds_buf == NULL) {
		error = ENOMEM;
		goto finally;
	}

#define	ENCODE_INT32(n, buf, len)	do {			\
	len = fsyscall_encode_int32((n), (buf), sizeof(buf));	\
	if (len == -1) {					\
		error = ENOMEM;					\
		goto finally;					\
	}							\
} while (0)
	ENCODE_INT32(nfds, nfds_buf, nfds_len);
	ENCODE_INT32(nreadfds, nreadfds_buf, nreadfds_len);
	ENCODE_INT32(nwritefds, nwritefds_buf, nwritefds_len);
	ENCODE_INT32(nexceptfds, nexceptfds_buf, nexceptfds_len);
	/*
	 * One more idea
	 * *************
	 *
	 * The following field tells that timeout is NULL or not NULL. This
	 * field can have more roles. For example, timeout must be usually NULL
	 * (for blocking) or zero (for polling). So this field can tell that
	 * timeout is zero with the value of "2". Such way can decrease bytes.
	 */
	ENCODE_INT32(timeout != NULL ? 1 : 0, timeout_buf, timeout_len);
#undef	ENCODE_INT32
#define	ENCODE_FDS(fds, buf, buf_len, len)	do {			\
	error = encode_fds(td, nfds, (fds), (buf), (buf_len), &(len));	\
	if (error != 0)							\
		goto finally;						\
} while (0)
	ENCODE_FDS(readfds, readfds_buf, readfds_buf_len, readfds_len);
	ENCODE_FDS(writefds, writefds_buf, writefds_buf_len, writefds_len);
	ENCODE_FDS(exceptfds, exceptfds_buf, exceptfds_buf_len, exceptfds_len);
#undef	ENCODE_FDS
#define	ENCODE_INT64(n, buf, len) do {				\
	len = fsyscall_encode_int64((n), (buf), sizeof(buf));	\
	if (len == -1) {					\
		error = ENOMEM;					\
		goto finally;					\
	}							\
} while (0)
	if (timeout != NULL) {
		ENCODE_INT64(timeout->tv_sec, sec_buf, sec_len);
		ENCODE_INT64(timeout->tv_usec, usec_buf, usec_len);
	}
	else
		sec_len = usec_len = 0;
#undef	ENCODE_INT64

	payload_size = nfds_len + nreadfds_len + readfds_len + nwritefds_len +
		       writefds_len + nexceptfds_len + exceptfds_len +
		       timeout_len + sec_len + usec_len;
	error = fmaster_write_command(td, CALL_SELECT);
	if (error != 0)
		goto finally;
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		goto finally;
	wfd = fmaster_wfd_of_thread(td);
#define	WRITE(buf, len)	do {				\
	error = fmaster_write(td, wfd, (buf), (len));	\
	if (error != 0)					\
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

	return (error);
}

static int
read_fds(struct thread *td, fd_set *fds, payload_size_t *len)
{
	payload_size_t nfds_len, payload_size, slave_fd_len;
	int error, local_fd, nfds, i, slave_fd;

	payload_size = 0;

	error = fmaster_read_int32(td, &nfds, &nfds_len);
	if (error != 0)
		return (error);
	payload_size += nfds_len;

	for (i = 0; i < nfds; i++) {
		error = fmaster_read_int32(td, &slave_fd, &slave_fd_len);
		if (error != 0)
			return (error);
		payload_size += slave_fd_len;

		error = fmaster_fd_of_slave_fd(td, slave_fd, &local_fd);
		if (error != 0)
			return (error);
		FD_SET(local_fd, fds);
	}

	*len = payload_size;

	return (0);
}

static int
read_result(struct thread *td, fd_set *readfds, fd_set *writefds, fd_set *exceptfds)
{
	payload_size_t actual_payload_size, errnum_len, exceptfds_len;
	payload_size_t payload_size, readfds_len, retval_len, writefds_len;
	command_t cmd;
	int errnum, error, retval;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != RET_SELECT)
		return (EPROTO);
	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);
	error = fmaster_read_int32(td, &retval, &retval_len);
	if (error != 0)
		return (error);

	switch (retval) {
	case -1:
		error = fmaster_read_int32(td, &errnum, &errnum_len);
		if (error != 0)
			return (error);
		actual_payload_size = retval_len + errnum_len;
		if (payload_size != actual_payload_size)
			return (EPROTO);
		return (errnum);
	case 0:
		readfds_len = writefds_len = exceptfds_len = 0;
		break;
	default:
		FD_ZERO(readfds);
		FD_ZERO(writefds);
		FD_ZERO(exceptfds);
		error = read_fds(td, readfds, &readfds_len);
		if (error != 0)
			return (error);
		error = read_fds(td, writefds, &writefds_len);
		if (error != 0)
			return (error);
		error = read_fds(td, exceptfds, &exceptfds_len);
		if (error != 0)
			return (error);
		break;
	}
	actual_payload_size = retval_len + readfds_len + writefds_len +
			      exceptfds_len;
	if (payload_size != actual_payload_size)
		return (EPROTO);

	td->td_retval[0] = retval;

	return (0);
}

int
sys_fmaster_select(struct thread *td, struct fmaster_select_args *uap)
{
	struct timeval *ptimeout, timeout;
	fd_set exceptfds, readfds, writefds;
	int error, nfds;

	nfds = uap->nd;

#define	INIT_FDS(u, k)	do {					\
	if ((u) != NULL) {					\
		error = copyin((u), (k), sizeof(*k));		\
		if (error != 0)					\
			return (error);				\
	}							\
	else							\
		FD_ZERO(k);					\
} while (0)
	INIT_FDS(uap->in, &readfds);
	INIT_FDS(uap->ou, &writefds);
	INIT_FDS(uap->ex, &exceptfds);
#undef	INIT_FDS
	if (uap->tv != NULL) {
		error = copyin(uap->tv, &timeout, sizeof(timeout));
		if (error != 0)
			return (error);
		ptimeout = &timeout;
	}
	else
		ptimeout = NULL;

	if (has_nonslave_fd(td, nfds, &readfds))
		return (EBADF);
	if (has_nonslave_fd(td, nfds, &writefds))
		return (EBADF);
	if (has_nonslave_fd(td, nfds, &exceptfds))
		return (EBADF);

	error = write_call(td, nfds, &readfds, &writefds, &exceptfds, ptimeout);
	if (error != 0)
		return (error);

	error = read_result(td, &readfds, &writefds, &exceptfds);
	if (error != 0)
		return (error);

#define	COPYOUT(u, k)	do {					\
	if ((u) != NULL) {					\
		error = copyout((u), (k), sizeof(*(k)));	\
		if (error == 0)					\
			return (error);				\
	}							\
} while (0)
	COPYOUT(uap->in, &readfds);
	COPYOUT(uap->ou, &writefds);
	COPYOUT(uap->ex, &exceptfds);
#undef	COPYOUT

	return (0);
}

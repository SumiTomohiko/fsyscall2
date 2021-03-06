#include <sys/param.h>
#include <sys/event.h>
#if defined(KLD_MODULE)
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/stddef.h>
#include <sys/systm.h>
#include <sys/un.h>
#else
#include <sys/un.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#endif

#include <fsyscall/private/command.h>
#if !defined(KLD_MODULE)
#include <fsyscall/private/die.h>
#endif
#include <fsyscall/private/encode.h>
#include <fsyscall/private/payload.h>

#define	BUFSIZE	64

#if defined(KLD_MODULE)
MALLOC_DEFINE(M_PAYLOAD, "payload", "payload");

#define	MALLOC_FLAGS		(M_ZERO | M_WAITOK)
#define	ALLOC_MEM(size)		malloc((size), M_PAYLOAD, MALLOC_FLAGS)
#define	REALLOC_MEM(addr, size)	realloc((addr), (size), M_PAYLOAD, MALLOC_FLAGS)
#define	FREE_MEM(addr)		free((addr), M_PAYLOAD)
#else
#define	ALLOC_MEM(size)		malloc((size))
#define	REALLOC_MEM(addr, size)	realloc((addr), (size))
#define	FREE_MEM(addr)		free((addr))
#endif

struct payload {
	payload_size_t buf_size;
	payload_size_t used_size;
	char *buf;
};

#if !defined(KLD_MODULE)
void
payload_dump(const struct payload *payload)
{
	payload_size_t i, size;
	const char *fmt = "payload %p[%d]: 0x%02x (%c)";
	char c, datum;

	size = payload->used_size;
	for (i = 0; i < size; i++) {
		datum = payload->buf[i];
		c = isprint(datum) ? datum : ' ';
		syslog(LOG_DEBUG, fmt, payload, i, 0xff & c, c);
	}
}
#endif

static int
realloc_buf_if_small(struct payload *payload, payload_size_t size)
{
	payload_size_t buf_size;
	char *buf;

	if (size <= payload->buf_size)
		return (0);

	buf_size = (size / BUFSIZE + 1) * BUFSIZE;
	buf = (char *)REALLOC_MEM(payload->buf, buf_size);
	if (buf == NULL)
		return (ENOMEM);
	payload->buf_size = buf_size;
	payload->buf = buf;

	return (0);
}

payload_size_t
fsyscall_payload_get_size(struct payload *payload)
{
	return (payload->used_size);
}

char *
fsyscall_payload_get(struct payload *payload)
{
	return (payload->buf);
}

int
fsyscall_payload_add(struct payload *payload, const char *buf,
		     payload_size_t size)
{
	int error;

	error = realloc_buf_if_small(payload, payload->used_size + size);
	if (error != 0)
		return (error);
	memcpy(payload->buf + payload->used_size, buf, size);
	payload->used_size += size;

	return (0);
}

static int
fsyscall_payload_add_data_with_length(struct payload *payload, const char *buf,
				      uint64_t len)
{
	int error;

	error = fsyscall_payload_add_uint64(payload, len);
	if (error != 0)
		return (error);
	error = fsyscall_payload_add(payload, buf, len);
	if (error != 0)
		return (error);

	return (error);
}

int
fsyscall_payload_add_sockaddr(struct payload *payload, struct sockaddr *name)
{
	struct sockaddr_un *addr = (struct sockaddr_un *)name;
	socklen_t len;
	int error;
	const char *path;

	if (name->sa_family != AF_LOCAL)
		return (EOPNOTSUPP);

	error = fsyscall_payload_add_uint8(payload, addr->sun_len);
	if (error != 0)
		return (error);
	error = fsyscall_payload_add_uint8(payload, addr->sun_family);
	if (error != 0)
		return (error);
	path = addr->sun_path;
	/*
	 * Some applications do not set sun_len. I must measure size of the
	 * socket address manually.
	 */
	len = strlen(path);
	error = fsyscall_payload_add_data_with_length(payload, path, len);
	if (error != 0)
		return (error);

	return (0);
}

#define	IMPLEMENT_ADD_X(name, type, bufsize, encode)			\
	int								\
	name(struct payload *payload, type n)				\
	{								\
		int error, len;						\
		char buf[bufsize];					\
									\
		len = encode(n, buf, sizeof(buf));			\
		if (len < 0)						\
			return (EMSGSIZE);				\
		error = fsyscall_payload_add(payload, buf, len);	\
		if (error != 0)						\
			return (error);					\
									\
		return (0);						\
	}
IMPLEMENT_ADD_X(fsyscall_payload_add_int16, int16_t, FSYSCALL_BUFSIZE_INT16,
		fsyscall_encode_int16)
IMPLEMENT_ADD_X(fsyscall_payload_add_int32, int32_t, FSYSCALL_BUFSIZE_INT32,
		fsyscall_encode_int32)
IMPLEMENT_ADD_X(fsyscall_payload_add_int64, int64_t, FSYSCALL_BUFSIZE_INT64,
		fsyscall_encode_int64)
IMPLEMENT_ADD_X(fsyscall_payload_add_uint8, uint8_t, FSYSCALL_BUFSIZE_UINT8,
		fsyscall_encode_uint8)
IMPLEMENT_ADD_X(fsyscall_payload_add_uint16, uint16_t, FSYSCALL_BUFSIZE_UINT16,
		fsyscall_encode_uint16)
IMPLEMENT_ADD_X(fsyscall_payload_add_uint32, uint32_t, FSYSCALL_BUFSIZE_UINT32,
		fsyscall_encode_uint32)
IMPLEMENT_ADD_X(fsyscall_payload_add_uint64, uint64_t, FSYSCALL_BUFSIZE_UINT64,
		fsyscall_encode_uint64)
#undef IMPLEMENT_ADD_X

int
fsyscall_payload_add_string(struct payload *payload, const char *s)
{
	int error;

	error = fsyscall_payload_add_data_with_length(payload, s, strlen(s));
	if (error != 0)
		return (error);

	return (0);
}

int
fsyscall_payload_add_sigset(struct payload *payload, sigset_t *set)
{
	int error, i;

	error = 0;
	for (i = 0; (error == 0) && (i < _SIG_WORDS); i++)
		error = fsyscall_payload_add_uint32(payload, set->__bits[i]);

	return (error);
}

int
fsyscall_payload_dispose(struct payload *payload)
{
	FREE_MEM(payload->buf);
	FREE_MEM(payload);

	return (0);
}

struct payload *
fsyscall_payload_create()
{
	struct payload *payload;
	char *buf = NULL;

	payload = (struct payload *)ALLOC_MEM(sizeof(*payload));
	if (payload == NULL)
		goto fail;
	payload->buf_size = BUFSIZE;
	payload->used_size = 0;
	buf = (char *)ALLOC_MEM(BUFSIZE);
	if (buf == NULL)
		goto fail;
	payload->buf = buf;

	return (payload);

fail:
	FREE_MEM(payload);
	return (NULL);
}

int
fsyscall_payload_add_kevent(struct payload *payload, struct kevent *kev)
{
	int error;

	error = fsyscall_payload_add_ulong(payload, kev->ident);
	if (error != 0)
		return (error);
	error = fsyscall_payload_add_short(payload, kev->filter);
	if (error != 0)
		return (error);
	error = fsyscall_payload_add_ushort(payload, kev->flags);
	if (error != 0)
		return (error);
	error = fsyscall_payload_add_uint(payload, kev->fflags);
	if (error != 0)
		return (error);
	error = fsyscall_payload_add_long(payload, kev->data);
	if (error != 0)
		return (error);
	if (kev->udata != NULL)
		return (EINVAL);
	error = fsyscall_payload_add_int(payload, KEVENT_UDATA_NULL);
	if (error != 0)
		return (error);

	return (0);
}

int
fsyscall_payload_add_timeval(struct payload *payload, const struct timeval *t)
{
	int error;

	error = fsyscall_payload_add_time(payload, t->tv_sec);
	if (error != 0)
		return (error);
	error = fsyscall_payload_add_suseconds(payload, t->tv_usec);
	if (error != 0)
		return (error);

	return (0);
}

int
fsyscall_payload_add_dirent(struct payload *payload,
			    const struct dirent *dirent)
{
	int error;

	error = fsyscall_payload_add_uint32(payload, dirent->d_fileno);
	if (error != 0)
		return (error);
	error = fsyscall_payload_add_uint8(payload, dirent->d_type);
	if (error != 0)
		return (error);
	error = fsyscall_payload_add_string(payload, dirent->d_name);
	if (error != 0)
		return (error);

	return (0);
}

#if !defined(KLD_MODULE)
struct payload *
payload_create()
{
	struct payload *payload;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		die(1, "failed to create a payload");

	return (payload);
}

#define	IMPLEMENT_ADD_X(name, type)					\
	void								\
	name(struct payload *payload, type n)				\
	{								\
		int error;						\
									\
		error = fsyscall_##name(payload, n);			\
		if (error != 0)						\
			die(1, "failed to add a datum to the payload");	\
	}
IMPLEMENT_ADD_X(payload_add_int16, int16_t)
IMPLEMENT_ADD_X(payload_add_int32, int32_t)
IMPLEMENT_ADD_X(payload_add_int64, int64_t)
IMPLEMENT_ADD_X(payload_add_uint8, uint8_t)
IMPLEMENT_ADD_X(payload_add_uint32, uint32_t)
IMPLEMENT_ADD_X(payload_add_uint64, uint64_t)
IMPLEMENT_ADD_X(payload_add_dirent, const struct dirent*);
IMPLEMENT_ADD_X(payload_add_kevent, struct kevent *);
IMPLEMENT_ADD_X(payload_add_sockaddr, struct sockaddr *);
#undef IMPLEMENT_ADD_X

void
payload_add(struct payload *payload, const char *buf, payload_size_t size)
{
	int error;

	error = fsyscall_payload_add(payload, buf, size);
	if (error != 0)
		die(1, "failed to add data to the payload");
}
#endif

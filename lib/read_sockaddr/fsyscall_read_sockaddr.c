#if defined(KLD_MODULE)
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/stddef.h>
#include <sys/systm.h>
#else
#include <errno.h>
#include <stddef.h>
#include <string.h>
#endif
#include <sys/un.h>

#include <fsyscall/private/read_sockaddr.h>

#if !defined(MIN)
#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#endif

#if !defined(KLD_MODULE)
#include <syslog.h>
#endif

static int
read_un(struct rsopts *opts, struct sockaddr_un *addr, payload_size_t *len)
{
	uint64_t size;
	payload_size_t size_len;
	int error;
	char *buf, *path;

	*len = 0;

	error = opts->rs_read_uint64(opts, &size, &size_len);
	if (error != 0)
		return (error);
	*len += size_len;

	buf = opts->rs_malloc(opts, size);
	if (buf == NULL)
		return (ENOMEM);

	error = opts->rs_read(opts, buf, size);
	if (error != 0)
		goto exit;
	*len += size;

	path = addr->sun_path;
	memcpy(path, buf, size);
	path[MIN(size, sizeof(addr->sun_path) - 1)] = '\0';
	error = 0;

exit:
	opts->rs_free(opts, buf);

	return (error);
}

int
fsyscall_read_sockaddr(struct rsopts *opts, struct sockaddr_storage *addr,
		       payload_size_t *len)
{
	payload_size_t addrlen, family_len, len_len;
	int error;

	*len = 0;

	error = opts->rs_read_uint8(opts, &addr->ss_len, &len_len);
	if (error != 0)
		return (error);
	*len += len_len;

	error = opts->rs_read_uint8(opts, &addr->ss_family, &family_len);
	if (error != 0)
		return (error);
	*len += family_len;
#if !defined(KLD_MODULE)
#endif

	switch (addr->ss_family) {
	case AF_UNIX:
		error = read_un(opts, (struct sockaddr_un *)addr, &addrlen);
		break;
	default:
		error = EPROTO;
		break;
	}
	if (error != 0)
		return (error);
	*len += addrlen;

	return (error);
}

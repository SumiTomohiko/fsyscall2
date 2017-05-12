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
#include <net/zlib.h>

/*#define	ENABLE_LOG_MD5*/
#if defined(ENABLE_LOG_MD5)
#include <sys/md5.h>
#endif

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/payload.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

static bool compressed_call_enabled = true;
static const char *sysname = "writev";

#define	COMPRESSION_LEVEL	3

static voidpf
zlib_alloc(voidpf opaque, uInt items, uInt size)
{

#if 0
	log(LOG_DEBUG,
	    "zlib_alloc: items=%d, size=%d, total=%d\n",
	    items, size, items * size);
#endif

	return (malloc(items * size, M_TEMP, M_WAITOK));
}

static void
zlib_free(voidpf opaque, voidpf address)
{

	free(address, M_TEMP);
}

static const char *
zliberror(int error)
{
#define	CASE(name)	case name: return #name

	switch (error) {
	CASE(Z_OK);
	CASE(Z_STREAM_END);
	CASE(Z_NEED_DICT);
	CASE(Z_ERRNO);
	CASE(Z_STREAM_ERROR);
	CASE(Z_DATA_ERROR);
	CASE(Z_MEM_ERROR);
	CASE(Z_BUF_ERROR);
	CASE(Z_VERSION_ERROR);
	default:
		return "unknown error";
	}

#undef	CASE
}

static int
compress_payload(char *dest, size_t destsize, char *src, size_t srcsize,
		 bool *success, payload_size_t *total_out)
{
	z_stream z;
	int error, zerror;

	bzero(&z, sizeof(z));
	z.zalloc = zlib_alloc;
	z.zfree = zlib_free;
	z.opaque = Z_NULL;
	z.data_type = Z_BINARY;
	zerror = deflateInit(&z, COMPRESSION_LEVEL);
	if (zerror != Z_OK)
		return (EINVAL);

	z.next_in = src;
	z.avail_in = srcsize;
	z.next_out = dest;
	z.avail_out = destsize;
	zerror = deflate(&z, Z_FINISH);
#if 1
	log(LOG_DEBUG,
	    "deflate: zerror=%d (%s), dest=%p, destsize=%zu, src=%p, srcsize=%z"
	    "u, z.next_in=%p, z.avail_in=%d, z.total_in=%lu, z.next_out=%p, z.a"
	    "vail_out=%d, z.total_out=%lu, z.msg=%s\n",
	    zerror, zliberror(zerror), dest, destsize, src, srcsize, z.next_in,
	    z.avail_in, z.total_in, z.next_out, z.avail_out, z.total_out,
	    z.msg != NULL ? z.msg : "NULL");
#endif
	switch (zerror) {
	case Z_STREAM_END:
		error = 0;
		*success = true;
		*total_out = z.total_out;
		break;
	case Z_OK:
		error = 0;
		*success = false;
		break;
	default:
		error = EINVAL;
		break;
	}

	zerror = deflateEnd(&z);
	if ((zerror != Z_OK) && (error == 0))
		return (EINVAL);

	return (error);
}

static int
write_compressed_call(struct thread *td, const char *buf, size_t bufsize)
{
	int error;

	error = fmaster_write_command(td, COMPRESSED_WRITEV_CALL);
	if (error != 0)
		return (error);
	error = fmaster_write_payload_size(td, bufsize);
	if (error != 0)
		return (error);
	error = fmaster_write(td, fmaster_wfd_of_thread(td), buf, bufsize);
	if (error != 0)
		return (error);

	return (0);
}

#if defined(ENABLE_LOG_MD5)
static void
log_md5(struct thread *td, const char *tag, const char *buf, size_t bufsize)
{
	MD5_CTX md5;
	int i, len;
	unsigned char digest[16];
	char s[256];

	MD5Init(&md5);
	MD5Update(&md5, buf, bufsize);
	MD5Final(digest, &md5);

	len = array_sizeof(digest);
	for (i = 0; i < len; i++)
		sprintf(&s[2 * i], "%02x", digest[i]);
	s[2 * len] = '\0';

	fmaster_log(td, LOG_DEBUG, "%s: %s md5=%s", sysname, tag, s);
}
#endif

static int
execute_compressed_call(struct thread *td, struct payload *payload,
			bool *success)
{
	struct malloc_type *mt;
	payload_size_t total_out;
	size_t bufsize;
	int error;
	char *buf, *p;

	mt = M_TEMP;

	bufsize = fsyscall_payload_get_size(payload);
	buf = (char *)malloc(bufsize, mt, M_WAITOK);
	if (buf == NULL)
		return (ENOMEM);

	p = fsyscall_payload_get(payload);
	error = compress_payload(buf, bufsize, p, bufsize, success, &total_out);
	if ((error != 0) || !*success)
		goto exit;
#if defined(ENABLE_LOG_MD5)
	log_md5(td, "uncompressed", p, bufsize);
	log_md5(td, "compressed", buf, total_out);
#endif
	error = write_compressed_call(td, buf, total_out);
	if (error != 0)
		goto exit;

exit:
	free(buf, mt);

	return (error);
}

static int
write_small_call(struct thread *td, struct payload *payload)
{
	int error;

	error = fmaster_write_payloaded_command(td, WRITEV_CALL, payload);

	return (error);
}

static int
execute_call(struct thread *td, struct fmaster_writev_args *uap, int lfd)
{
	struct payload *payload;
	struct iovec *iov, *iovp;
	payload_size_t size;
	size_t len;
	u_int i, iovcnt;
	bool success;
	int error;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);
	error = fsyscall_payload_add_int(payload, lfd);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_uint(payload, uap->iovcnt);
	if (error != 0)
		goto exit;
	iovcnt = uap->iovcnt;
	iovp = uap->iovp;
	for (i = 0; i < iovcnt; i++) {
		iov = &iovp[i];
		len = iov->iov_len;
		error = fsyscall_payload_add_size(payload, len);
		if (error != 0)
			goto exit;
		error = fsyscall_payload_add(payload, iov->iov_base, len);
		if (error != 0)
			goto exit;
	}

	size = fsyscall_payload_get_size(payload);
	if (!compressed_call_enabled || (size < 1024)) {
		error = write_small_call(td, payload);
		if (error != 0)
			goto exit;
	}
	else {
		error = execute_compressed_call(td, payload, &success);
		if (error != 0)
			goto exit;
		if (!success) {
			error = write_small_call(td, payload);
			if (error != 0)
				goto exit;
		}
	}

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
fmaster_writev_main(struct thread *td, struct fmaster_writev_args *uap)
{
	struct writev_args a;
	enum fmaster_file_place place;
	int error, lfd;

	error = fmaster_get_vnode_info(td, uap->fd, &place, &lfd);
	if (error != 0)
		return (error);
	switch (place) {
	case FFP_MASTER:
		memcpy(&a, uap, sizeof(a));
		a.fd = lfd;
		error = sys_writev(td, &a);
		if (error != 0)
			return (error);
		return (0);
	case FFP_SLAVE:
		break;
	case FFP_PENDING_SOCKET:
		fmaster_log(td, LOG_INFO,
			    "%s: called for a pending socket: fd=%d, lfd=%d",
			    sysname, uap->fd, lfd);
		return (ENOTCONN);
	default:
		return (EBADF);
	}

	error = execute_call(td, uap, lfd);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_generic32(td, WRITEV_RETURN);
	if (error != 0)
		return (error);
	return (0);
}

int
sys_fmaster_writev(struct thread *td, struct fmaster_writev_args *uap)
{
	struct timeval time_start;
	int error;

	fmaster_log(td, LOG_DEBUG,
		    "%s: started: fd=%d, iovp=%p, iovcnt=%u",
		    sysname, uap->fd, uap->iovp, uap->iovcnt);
	microtime(&time_start);

	error = fmaster_writev_main(td, uap);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

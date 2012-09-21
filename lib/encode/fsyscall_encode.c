#if !defined(KLD_MODULE)
#include <assert.h>
#endif

#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>

#if !defined(KLD_MODULE)
#define	ASSERT(expr)	assert(expr)
#else
/* TODO: Implement here. */
#define	ASSERT(expr)
#endif

#define	IMPLEMENT_DECODE_X(type, name)			\
type							\
name(char *buf, int bufsize)				\
{							\
	type n;						\
	int i;						\
							\
	ASSERT((buf[bufsize - 1] & 0x80) == 0);		\
							\
	n = 0;						\
	for (i = 0; i < bufsize; i++)			\
		n += (buf[i] & 0x7f) << (7 * i);	\
							\
	return (n);					\
}

IMPLEMENT_DECODE_X(command_t, fsyscall_decode_command)
IMPLEMENT_DECODE_X(int32_t, fsyscall_decode_int32)
IMPLEMENT_DECODE_X(int64_t, fsyscall_decode_int64)

static int
encode_zero(char *buf, int bufsize)
{
	ASSERT(0 < bufsize);

	*buf = 0;
	return (1);
}

#define	IMPLEMENT_ENCODE_X(type, name)					\
int									\
name(type n, char *buf, int bufsize)					\
{									\
	type m;								\
	int pos;							\
									\
	if (n == 0)							\
		return (encode_zero(buf, bufsize));			\
									\
	m = n;								\
	pos = 0;							\
	while ((m != 0) && (pos < bufsize)) {				\
		buf[pos] = (m & 0x7f) | ((m & ~0x7f) != 0 ? 0x80 : 0);	\
									\
		m = m >> 7;						\
		pos++;							\
	}								\
	ASSERT(m == 0);							\
									\
	return (pos);							\
}

IMPLEMENT_ENCODE_X(uint32_t, fsyscall_encode_uint32)
IMPLEMENT_ENCODE_X(uint64_t, fsyscall_encode_uint64)

int
fsyscall_encode_int32(int32_t n, char *buf, int bufsize)
{
	return (fsyscall_encode_uint32((uint32_t)n, buf, bufsize));
}

int
fsyscall_encode_int64(int64_t n, char *buf, int bufsize)
{
	return (fsyscall_encode_uint64((uint64_t)n, buf, bufsize));
}

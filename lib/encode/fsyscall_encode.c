#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#if !defined(KLD_MODULE)
#include <fsyscall/private/die.h>
#endif

#define	IMPLEMENT_DECODE_X(type, name)				\
int								\
name(char *buf, int bufsize, type *dest)			\
{								\
	type n;							\
	int i;							\
								\
	if ((buf[bufsize - 1] & 0x80) != 0)			\
		return (-1);					\
								\
	n = 0;							\
	for (i = 0; i < bufsize; i++)				\
		n += ((type)(buf[i] & 0x7f)) << (7 * i);	\
	*dest = n;						\
								\
	return (0);						\
}

IMPLEMENT_DECODE_X(command_t, fsyscall_decode_command)
IMPLEMENT_DECODE_X(int8_t, fsyscall_decode_int8)
IMPLEMENT_DECODE_X(int16_t, fsyscall_decode_int16)
IMPLEMENT_DECODE_X(int32_t, fsyscall_decode_int32)
IMPLEMENT_DECODE_X(int64_t, fsyscall_decode_int64)

#if !defined(KLD_MODULE)
#define	IMPLEMENT_DECODE_OR_DIE_X(type, name, decoder)	\
type							\
name(char *buf, int bufsize)				\
{							\
	type dest;					\
							\
	if (decoder(buf, bufsize, &dest) != 0)		\
		diex(-1, "invalid numeric sequence");	\
	return (dest);					\
}
IMPLEMENT_DECODE_OR_DIE_X(command_t, decode_command, fsyscall_decode_command)
IMPLEMENT_DECODE_OR_DIE_X(int8_t, decode_int8, fsyscall_decode_int8)
IMPLEMENT_DECODE_OR_DIE_X(int32_t, decode_int32, fsyscall_decode_int32)
IMPLEMENT_DECODE_OR_DIE_X(int64_t, decode_int64, fsyscall_decode_int64)
#endif

static int
encode_zero(char *buf, int bufsize)
{
	if (bufsize <= 0)
		return (-1);

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
	return (m == 0 ? pos : -1);					\
}

IMPLEMENT_ENCODE_X(uint8_t, fsyscall_encode_uint8)
IMPLEMENT_ENCODE_X(uint16_t, fsyscall_encode_uint16)
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

#if !defined(KLD_MODULE)
#define	IMPLEMENT_ENCODE_OR_DIE_X(type, name, encoder)	\
int							\
name(type n, char *dest, int dest_size)			\
{							\
	int size = encoder(n, dest, dest_size);		\
	if (size < 0)					\
		diex(-1, "cannot encode");		\
	return (size);					\
}
IMPLEMENT_ENCODE_OR_DIE_X(int32_t, encode_int32, fsyscall_encode_int32)
IMPLEMENT_ENCODE_OR_DIE_X(int64_t, encode_int64, fsyscall_encode_int64)
IMPLEMENT_ENCODE_OR_DIE_X(uint8_t, encode_uint8, fsyscall_encode_uint8)
IMPLEMENT_ENCODE_OR_DIE_X(uint16_t, encode_uint16, fsyscall_encode_uint16)
IMPLEMENT_ENCODE_OR_DIE_X(uint32_t, encode_uint32, fsyscall_encode_uint32)
IMPLEMENT_ENCODE_OR_DIE_X(uint64_t, encode_uint64, fsyscall_encode_uint64)
#endif

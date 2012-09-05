#include <fsyscall/encode.h>

int
fsyscall_decode_int(char *buf, int bufsize)
{
	int i, n = 0;

	for (i = 0; i < bufsize; i++)
		n += (n << 7) + (buf[i] & 0x7f);

	return (n);
}

static int
encode_uint_zero(char *buf, int bufsize)
{
	if (bufsize < 1)
		return (0);
	*buf = 0;
	return (1);
}

int
fsyscall_encode_uint(unsigned int n, char *buf, int bufsize)
{
	unsigned int m = n;
	int pos = 0;

	if (n == 0)
		return (encode_uint_zero(buf, bufsize));

	while ((m != 0) && (pos < bufsize)) {
		buf[pos] = (m & 0x7f) | ((m & ~0x7f) != 0 ? 0x80 : 0);

		m = m >> 7;
		pos++;
	}
	if (m != 0)
		return (0);

	return (pos);
}

int
fsyscall_encode_int(int n, char *buf, int bufsize)
{
	return (fsyscall_encode_uint((unsigned int)n, buf, bufsize));
}

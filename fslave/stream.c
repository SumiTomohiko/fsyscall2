#include <sys/param.h>
#include <stdio.h>
#include <string.h>

#include <fsyscall/private/die.h>
#include <fsyscall/private/fslave/stream.h>

static char dumpbuf[64];

static const char *
dump(const struct stream *st)
{

	snprintf(dumpbuf, sizeof(dumpbuf),
		 "stream(st_p=%p, st_end=%p)", st->st_p, st->st_end);

	return (dumpbuf);
}

#define	COMPUTE_BITS(p, i)	((0x7f & *(p)) << (7 * (i)))

#define	IMPLEMENT_GETTER(type, name)					\
type									\
name(struct stream *st)							\
{									\
	type n;								\
	int i;								\
	const char *end, *p;						\
									\
	end = MIN(&st->st_p[8 * sizeof(type) / 7 + 1], st->st_end);	\
									\
	n = 0;								\
	for (p = st->st_p, i = 0;					\
	     (p < end) && ((0x80 & *p) == 0x80);			\
	     p++, i++)							\
		n += COMPUTE_BITS(p, i);				\
	if (p == end)							\
		diex(1,							\
		     "stream has been finished: st=%s, p=%p, end=%p",	\
		     dump(st), p, end);					\
	die_if_false((0x80 & *p) == 0, ("illegal numeric sequence"));	\
	n += COMPUTE_BITS(p, i);					\
	p++;								\
									\
	st->st_p = p;							\
									\
	return (n);							\
}

IMPLEMENT_GETTER(uint8_t, stream_get_uint8)
IMPLEMENT_GETTER(uint16_t, stream_get_uint16)
IMPLEMENT_GETTER(uint32_t, stream_get_uint32)
IMPLEMENT_GETTER(uint64_t, stream_get_uint64)

void
stream_init(struct stream *st, const char *buf, size_t bufsize)
{

	st->st_p = buf;
	st->st_end = &buf[bufsize];
}

void
stream_get(struct stream *st, void *buf, size_t bufsize)
{
	const char *end;

	end = &st->st_p[bufsize];
	if (st->st_end < end)
		diex(1, "stream overflow");

	memcpy(buf, st->st_p, bufsize);
	st->st_p += bufsize;
}

#if defined(TEST_STREAM)
/*
 * $ clang -DTEST_STREAM -Ilib/encode -Iinclude -Llib/die fslave/stream.c -ldie
 */
#include <stdint.h>

#include <fsyscall/private/encode.h>

#include <fsyscall_encode.c>

static void
printbuf(const char *buf, int bufsize)
{
	int i;
	const char *sep;

	printf("buf=%p-%p\n", buf, &buf[bufsize]);

	sep = "";
	for (i = 0; i < bufsize; i++) {
		printf("%s0x%02x", sep, (unsigned char)buf[i]);
		sep = " ";
	}

	printf("\n");
}

#define	IMPLEMENT_TEST(name, type, min, max, encode, get)	\
static void							\
name()								\
{								\
	struct stream st;					\
	long l;							\
	type m, n;						\
	int len;						\
	char buf[8192];						\
								\
	n = (min);						\
	for (;;) {						\
		len = encode(n, buf, sizeof(buf));		\
		if (len == -1)					\
			diex(1, "encode error");			\
		stream_init(&st, buf, len);			\
		m = get(&st);					\
		l = n;						\
		printf("%s: n=%ld, %s\n",			\
		       #name, l, n == m ? "OK" : "NG");		\
								\
		if (n == (max))					\
			break;					\
		n++;						\
	}							\
}

IMPLEMENT_TEST(test_uint8, uint8_t, 0, UINT8_MAX, fsyscall_encode_uint8,
	       stream_get_uint8)
IMPLEMENT_TEST(test_uint32, uint32_t, 0, UINT32_MAX, fsyscall_encode_uint32,
	       stream_get_uint32)
IMPLEMENT_TEST(test_uint64, uint64_t, 0, UINT64_MAX, fsyscall_encode_uint64,
	       stream_get_uint64)
#if 0
IMPLEMENT_TEST(test_int8, int8_t, INT8_MIN, INT8_MAX, fsyscall_encode_int8,
	       stream_get_int8)
#endif
IMPLEMENT_TEST(test_int32, int32_t, INT32_MIN, INT32_MAX, fsyscall_encode_int32,
	       stream_get_int32)
IMPLEMENT_TEST(test_int64, int64_t, INT64_MIN, INT64_MAX, fsyscall_encode_int64,
	       stream_get_int64)

static void
test_uint32_16384()
{
	struct stream st;
	uint32_t n, testee;
	int len;
	char buf[8192];

	testee = 16384;

	printf("test_uint32_16384: testee=%d (0x%x)\n", testee, testee);

	len = fsyscall_encode_uint32(testee, buf, sizeof(buf));
	if (len == -1)
		diex(1, "encode error");
	printbuf(buf, len);

	stream_init(&st, buf, len);
	n = stream_get_uint32(&st);

	printf("test_uint32_16384: n=%d, %s\n", n, testee == n ? "OK" : "NG");
}

int
main(int argc, const char *argv[])
{

	test_uint8();
	test_uint32();
	test_uint64();
#if 0
	test_int8();
#endif
	test_int32();
	test_int64();

#if 0
	test_uint32_16384();
#endif

	return (0);
}
#endif

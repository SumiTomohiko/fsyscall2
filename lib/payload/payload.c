#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <fsyscall/private/command.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/malloc_or_die.h>

#define	BUFSIZE	64

struct payload {
	payload_size_t buf_size;
	payload_size_t used_size;
	char *buf;
};

static void
realloc_buf_if_small(struct payload *payload, payload_size_t size)
{
	payload_size_t buf_size;
	char *buf;

	if (size <= payload->buf_size)
		return;

	buf_size = (size / BUFSIZE + 1) * BUFSIZE;
	buf = (char *)realloc(payload->buf, buf_size);
	if (buf == NULL)
		die(1, "realloc(3) failed");
	payload->buf_size = buf_size;
	payload->buf = buf;
}

payload_size_t
payload_get_size(struct payload *payload)
{
	return (payload->used_size);
}

char *
payload_get(struct payload *payload)
{
	return (payload->buf);
}

void
payload_add(struct payload *payload, const char *buf, payload_size_t size)
{

	realloc_buf_if_small(payload, payload->used_size + size);
	memcpy(payload->buf + payload->used_size, buf, size);
	payload->used_size += size;
}

void
payload_add_uint64(struct payload *payload, uint64_t n)
{
	int len;
	char buf[FSYSCALL_BUFSIZE_UINT64];

	len = fsyscall_encode_uint64(n, buf, sizeof(buf));
	if (len < 0)
		die(1, "Cannot encode uint64_t");
	payload_add(payload, buf, len);
}

void
payload_dispose(struct payload *payload)
{
	free(payload->buf);
	free(payload);
}

struct payload *
payload_create()
{
	struct payload *payload;

	payload = (struct payload *)malloc_or_die(sizeof(*payload));
	payload->buf_size = BUFSIZE;
	payload->used_size = 0;
	payload->buf = (char *)malloc_or_die(BUFSIZE);

	return (payload);
}

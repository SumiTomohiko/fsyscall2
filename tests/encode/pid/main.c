#include <sys/types.h>
#include <sys/limits.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fsyscall/private.h>
#include <fsyscall/private/encode.h>

static void
test_pid(pid_t pid)
{
	pid_t actual;
	int i, size;
	char buf[FSYSCALL_BUFSIZE_INT32];
	const char *fmt = "expected=%d (0x%x), actual=%d (0x%x)\n";

	size = fsyscall_encode_int32(pid, buf, array_sizeof(buf));
	actual = fsyscall_decode_int32(buf, size);
	printf(fmt, pid, pid, actual, actual);
	for (i = 0; i < size; i++)
		printf("buf[%d]=0x%02x (%d)\n", i, 0xff & buf[i], buf[i]);
	if (actual != pid)
		exit(1);
}

int
main(int argc, char *argv[])
{
	pid_t i;

	for (i = 0; i < INT_MAX; i++)
		test_pid(i);

	return (0);
}

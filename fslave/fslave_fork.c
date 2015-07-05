/**
 * THIS FILE WAS GENERATED BY tools/makesyscalls.py. DON'T EDIT.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fslave.h>
#include <fsyscall/private/io.h>

static void
execute_call(struct slave *slave, int *retval, int *errnum)
{
	payload_size_t actual_payload_size, payload_size;
	int rfd;

	rfd = slave->rfd;
	payload_size = read_payload_size(rfd);

	actual_payload_size = 0;
	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	*retval = fork();
	*errnum = errno;
}

void
process_fork(struct slave *slave)
{
	int errnum, retval;

	execute_call(slave, &retval, &errnum);
	return_int(slave, FORK_RETURN, retval, errnum);
}

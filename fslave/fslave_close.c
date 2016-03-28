#include <sys/types.h>
#include <sys/event.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fslave.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/io_or_die.h>

static void
execute_call(struct slave_thread *slave_thread, int *retval, int *errnum)
{
	sigset_t oset;
	payload_size_t actual_payload_size, payload_size;
	int fd, fd_len, rfd;

	rfd = slave_thread->fsth_rfd;
	payload_size = read_payload_size(rfd);

	fd = read_int32(rfd, &fd_len);

	actual_payload_size = fd_len;
	die_if_payload_size_mismatched(payload_size, actual_payload_size);

	suspend_signal(slave_thread, &oset);
	*retval = close(fd);
	*errnum = errno;
	resume_signal(slave_thread, &oset);
}

void
process_close(struct slave_thread *slave_thread)
{
	int errnum, retval;

	execute_call(slave_thread, &retval, &errnum);
	return_int(slave_thread, CLOSE_RETURN, retval, errnum);
}

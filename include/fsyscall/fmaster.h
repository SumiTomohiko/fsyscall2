#if !defined(FSYSCALL_FMASTER_H_INCLUDED)
#define FSYSCALL_FMASTER_H_INCLUDED

#include <sys/cdefs.h>
#include <sys/malloc.h>
#include <sys/proc.h>

#define	MAX_FD	1024

struct master_data {
	int rfd;
	int wfd;

	/*
	 * fds - What is this?
	 *
	 * A master process handles two kinds of file descriptors. One is fds
	 * opened in the slave process (slave fd), another one is fds opened in
	 * the master process (master fd), like pipes. In some cases, a slave fd
	 * may be same as a master fd. So, if a master process requests open(2),
	 * and the slave process successed the request, the fmaster kernel
	 * module returns a virtual fd. This virtual fd is index of
	 * master_data::fds.
	 *
	 * The actual fds are stored in this array. If a fd is a slave fd, two
	 * less significant bits are 01. If a fd is a master fd, two less
	 * significant bits are 11. You can get the actual fd in the slave
	 * process with (fds[fd] >> 2), you can also get the actual fd in the
	 * master process with the same expression.
	 *
	 * If a fd is unused, fds[fd] is zero.
	 */
	int fds[MAX_FD];
};

int sys_fsyscall_write_int(struct thread *, int);
int sys_fsyscall_write_str(struct thread *, const char*);
int sys_fsyscall_write_syscall(struct thread *, int);

#endif

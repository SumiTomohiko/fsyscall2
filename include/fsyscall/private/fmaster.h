#if !defined(FSYSCALL_FMASTER_H_INCLUDED)
#define FSYSCALL_FMASTER_H_INCLUDED

#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/malloc.h>
#include <sys/proc.h>

#include <fsyscall/private/command.h>

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

command_t	fmaster_read_command(struct thread *, int);
int32_t		fmaster_read_int32(struct thread *, int, int *);
void		fmaster_read_or_die(struct thread *, int, void *, size_t);
#define		fmaster_read_uint32(td, fd, psize) \
			((uint32_t)fmaster_read_int32((td), (fd), (psize)))

void	fmaster_write_command(struct thread *, command_t);
void	fmaster_write_int32(struct thread *, int32_t);
void	fmaster_write_or_die(struct thread *, int, const void *, size_t);
#define	fmaster_write_uint32(td, n)	fmaster_write_int32((td), (int32_t)(n))
#define	fmaster_write_payload_size	fmaster_write_uint32

int	fmaster_rfd_of_thread(struct thread *);
int	fmaster_wfd_of_thread(struct thread *);

int	fmaster_read_numeric_sequence(struct thread *, int, char *, int);

#define	SLAVE_FD2FD(fd)		(((fd) << 2) + 0x01)
#define	MASTER_FD2FD(fd)	(((fd) << 2) + 0x03)

int	fmaster_execute_return_generic(struct thread *, command_t);

#endif

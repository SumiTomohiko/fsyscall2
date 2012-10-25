#if !defined(FSYSCALL_FMASTER_H_INCLUDED)
#define FSYSCALL_FMASTER_H_INCLUDED

#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/systm.h>

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

int	fmaster_read_command(struct thread *, command_t *);
int	fmaster_read_int16(struct thread *, int16_t *, int *);
int	fmaster_read_int32(struct thread *, int32_t *, int *);
int	fmaster_read_int64(struct thread *, int64_t *, int *);
int	fmaster_read_payload_size(struct thread *, payload_size_t *);
int	fmaster_read(struct thread *, int, void *, size_t);
int	fmaster_read_to_userspace(struct thread *, int, void *, size_t);
#define	fmaster_read_uint16(td, dest, size) \
			fmaster_read_int16((td), (int16_t *)(dest), (size))
#define	fmaster_read_uint32(td, dest, size) \
			fmaster_read_int32((td), (int32_t *)(dest), (size))
#define	fmaster_read_uint64(td, dest, size) \
			fmaster_read_int64((td), (int64_t *)(dest), (size))

int	fmaster_write(struct thread *, int, const void *, size_t);
int	fmaster_write_command(struct thread *, command_t);
int	fmaster_write_int32(struct thread *, int32_t);
#define	fmaster_write_uint32(td, n)	fmaster_write_int32((td), (int32_t)(n))
int	fmaster_write_from_userspace(struct thread *, int, const void *, size_t);
#define	fmaster_write_payload_size	fmaster_write_uint32

int	fmaster_rfd_of_thread(struct thread *);
int	fmaster_wfd_of_thread(struct thread *);

#define	SLAVE_FD2FD(fd)		(((fd) << 2) + 0x01)
#define	MASTER_FD2FD(fd)	(((fd) << 2) + 0x03)

int	fmaster_execute_return_generic(struct thread *, command_t);

#define	LOG(td, pri, fmt, ...)	do {				\
	const char *__fmt__ = "fmaster[%d]: " fmt "\n";		\
	log((pri), __fmt__, (td)->td_proc->p_pid, __VA_ARGS__);	\
} while (0)

#endif

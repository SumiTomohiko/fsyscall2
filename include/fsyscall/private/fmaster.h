#if !defined(FSYSCALL_FMASTER_H_INCLUDED)
#define FSYSCALL_FMASTER_H_INCLUDED

#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <fsyscall/private/command.h>
#include <fsyscall/private/payload.h>

#define	FD_NUM	1024

enum fmaster_fd_type {
	FD_CLOSED,
	FD_SLAVE,
	FD_MASTER
};

struct fmaster_fd {
	enum fmaster_fd_type fd_type;
	int fd_local;
};

#define	DATA_TOKEN_SIZE	64

struct fmaster_data {
	int rfd;
	int wfd;
	int kq;		/* kqueue for rfd */
	size_t rfdlen;	/* readable data length in the buffer of rfd */

	/*
	 * fds - What is this?
	 *
	 * A master process handles two kinds of file descriptors. One is fds
	 * opened in the slave process (slave fd), another one is fds opened in
	 * the master process (master fd), like pipes. In some cases, a slave fd
	 * may be same as a master fd. So, if a master process requests open(2),
	 * and the slave process successed the request, the fmaster kernel
	 * module returns a virtual fd. This virtual fd is index of
	 * fmaster_data::fds.
	 */
	struct fmaster_fd fds[FD_NUM];

	char fork_sock[MAXPATHLEN];
	uint64_t token_size;
	char token[DATA_TOKEN_SIZE];
};

int	fmaster_read_command(struct thread *, command_t *);
int	fmaster_read_int8(struct thread *, int8_t *, int *);
int	fmaster_read_int16(struct thread *, int16_t *, int *);
int	fmaster_read_int32(struct thread *, int32_t *, int *);
int	fmaster_read_int64(struct thread *, int64_t *, int *);
int	fmaster_read_uint64(struct thread *, uint64_t *, int *);
int	fmaster_read_payload_size(struct thread *, payload_size_t *);
int	fmaster_read_sockaddr(struct thread *, struct sockaddr_storage *,
			      int *);
int	fmaster_read(struct thread *, int, void *, size_t);
int	fmaster_read_to_userspace(struct thread *, int, void *, size_t);
#define	fmaster_read_uint8(td, dest, size) \
			fmaster_read_int8((td), (int8_t *)(dest), (size))
#define	fmaster_read_uint16(td, dest, size) \
			fmaster_read_int16((td), (int16_t *)(dest), (size))
#define	fmaster_read_uint32(td, dest, size) \
			fmaster_read_int32((td), (int32_t *)(dest), (size))
#define	fmaster_read_uint64(td, dest, size) \
			fmaster_read_int64((td), (int64_t *)(dest), (size))
#define	fmaster_read_short	fmaster_read_int16
#define	fmaster_read_int	fmaster_read_int32
#define	fmaster_read_long	fmaster_read_int64
#define	fmaster_read_ushort	fmaster_read_uint16
#define	fmaster_read_uint	fmaster_read_uint32
#define	fmaster_read_ulong	fmaster_read_uint64
#define	fmaster_read_socklen	fmaster_read_uint32

int	fmaster_write(struct thread *, int, const void *, size_t);
int	fmaster_write_command(struct thread *, command_t);
int	fmaster_write_int32(struct thread *, int32_t);
#define	fmaster_write_uint32(td, n)	fmaster_write_int32((td), (int32_t)(n))
int	fmaster_write_from_userspace(struct thread *, int, const void *, size_t);
#define	fmaster_write_payload_size	fmaster_write_uint32
int	fmaster_write_payloaded_command(struct thread *, command_t,
					struct payload *);

struct fmaster_data *
	fmaster_data_of_thread(struct thread *);
int	fmaster_rfd_of_thread(struct thread *);
int	fmaster_wfd_of_thread(struct thread *);
struct fmaster_fd *
	fmaster_fds_of_thread(struct thread *);

struct fmaster_data *
	fmaster_create_data(struct thread *);
void	fmaster_delete_data(struct fmaster_data *);

void	fmaster_close_fd(struct thread *, int);
int	fmaster_fd_of_master_fd(struct thread *, int, int *);
int	fmaster_fd_of_slave_fd(struct thread *, int, int *);
int	fmaster_type_of_fd(struct thread *, int, enum fmaster_fd_type *);

int	fmaster_execute_close(struct thread *, int);
int	fmaster_execute_return_optional32(struct thread *, command_t,
					  int (*)(struct thread *, int,
						  payload_size_t *, void *),
					  void *);
int	fmaster_execute_return_generic32(struct thread *, command_t);
int	fmaster_execute_return_generic64(struct thread *, command_t);
int	fmaster_execute_connect_protocol(struct thread *td, const char *command,
					 command_t call_command,
					 command_t return_command, int s,
					 struct sockaddr *name,
					 socklen_t namelen);
int	fmaster_execute_accept_protocol(struct thread *, const char *,
					command_t, command_t, int,
					struct sockaddr *, socklen_t *);
int	fmaster_register_fd(struct thread *, enum fmaster_fd_type, int, int *);
int	fmaster_register_fd_at(struct thread *td, enum fmaster_fd_type type,
			       int mfd, int sfd);
int	fmaster_return_fd(struct thread *, enum fmaster_fd_type, int);

int	fmaster_is_master_file(struct thread *, const char *);

int	fmaster_initialize_kqueue(struct thread *, struct fmaster_data *);
void	fmaster_schedtail(struct thread *);

/* misc */
typedef unsigned int flag_t;

struct flag_definition {
	flag_t value;
	const char *name;
};

enum fmaster_side {
	SIDE_MASTER = 0x01,
	SIDE_SLAVE = 0x02,
	SIDE_BOTH = SIDE_MASTER | SIDE_SLAVE
};

#define	DEFINE_FLAG(name)	{ name, #name }

void	fmaster_chain_flags(char *, size_t, flag_t, struct flag_definition[],
			    size_t);
long	fmaster_subtract_timeval(const struct timeval *,
				 const struct timeval *);
void	fmaster_log_syscall_end(struct thread *, const char *,
				const struct timeval *, int);
const char *
	fmaster_get_sockopt_name(int);

#define	LOG(td, pri, fmt, ...)	do {				\
	const char *__fmt__ = "fmaster[%d]: " fmt "\n";		\
	log((pri), __fmt__, (td)->td_proc->p_pid, __VA_ARGS__);	\
} while (0)

#define	array_sizeof(a)		(sizeof(a) / sizeof(a[0]))

MALLOC_DECLARE(M_FMASTER);

#endif

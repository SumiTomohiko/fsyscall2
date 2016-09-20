#if !defined(FSYSCALL_FMASTER_H_INCLUDED)
#define FSYSCALL_FMASTER_H_INCLUDED

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <vm/uma.h>

#include <fsyscall/private/command.h>
#include <fsyscall/private/payload.h>

enum fmaster_file_place {
	FFP_MASTER,
	FFP_SLAVE,
	FFP_PENDING_SOCKET
};

#define	VNODE_DESC_LEN	256
#define	FILES_NUM	256

struct fmaster_pending_sock {
	int	fps_domain;
	int	fps_type;
	int	fps_protocol;
	bool	fps_reuseaddr;
	bool	fps_nonblocking;
};

struct fmaster_data;

#define	SLAVE_PID_UNKNOWN	(-1)

/* I/O */
int	fmaster_read_command(struct thread *, command_t *);
int	fmaster_read_int8(struct thread *, int8_t *, payload_size_t *);
int	fmaster_read_int16(struct thread *, int16_t *, payload_size_t *);
int	fmaster_read_int32(struct thread *, int32_t *, payload_size_t *);
int	fmaster_read_int64(struct thread *, int64_t *, payload_size_t *);
int	fmaster_read_uint64(struct thread *, uint64_t *, payload_size_t *);
int	fmaster_read_payload_size(struct thread *, payload_size_t *);
int	fmaster_read_sockaddr(struct thread *, struct sockaddr_storage *,
			      payload_size_t *);
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
#define	fmaster_read_ssize	fmaster_read_int64
#define	fmaster_read_ushort	fmaster_read_uint16
#define	fmaster_read_uint	fmaster_read_uint32
#define	fmaster_read_ulong	fmaster_read_uint64
#define	fmaster_read_pid	fmaster_read_int32
#define	fmaster_read_uid	fmaster_read_uint32
#define	fmaster_read_gid	fmaster_read_uint32
#define	fmaster_read_socklen	fmaster_read_uint32

int	fmaster_write(struct thread *, int, const void *, size_t);
int	fmaster_write_command(struct thread *, command_t);
int	fmaster_write_int32(struct thread *, int32_t);
#define	fmaster_write_uint32(td, n)	fmaster_write_int32((td), (int32_t)(n))
int	fmaster_write_from_userspace(struct thread *, int, const void *, size_t);
#define	fmaster_write_payload_size	fmaster_write_uint32
int	fmaster_write_payloaded_command(struct thread *, command_t,
					struct payload *);

/* thread */
int	fmaster_rfd_of_thread(struct thread *);
int	fmaster_wfd_of_thread(struct thread *);
void	fmaster_set_slave_pid(struct thread *, pid_t);
pid_t	fmaster_get_slave_pid(struct thread *);
void	fmaster_end_thread_creating(struct thread *);
void	fmaster_start_thread_creating(struct thread *);

/* lifecycle */
int	fmaster_add_thread(struct thread *, lwpid_t, const char *, uint64_t);
int	fmaster_create_data(struct thread *, int, int, const char *,
			    struct fmaster_data **);
int	fmaster_create_data2(struct thread *, pid_t, lwpid_t, const char *,
			     size_t, struct fmaster_data **);
void	fmaster_delete_data(struct fmaster_data *);
int	fmaster_release_thread(struct thread *);

/* vnode operations */
void	fmaster_lock_file_table(struct thread *);
void	fmaster_unlock_file_table(struct thread *);
int	fmaster_get_vnode_info(struct thread *, int, enum fmaster_file_place *,
			       int *);
int	fmaster_get_vnode_info2(struct thread *, int, enum fmaster_file_place *,
				int *, const char **);

/* file operations */
int	fmaster_register_file(struct thread *, short, enum fmaster_file_place,
			      int, int *, const char *);
int	fmaster_unref_fd(struct thread *, int, enum fmaster_file_place *, int *,
			 int *);
int	fmaster_dup(struct thread *, int, int *);
int	fmaster_dup2(struct thread *, int, int);
int	fmaster_pipe(struct thread *, int);
int	fmaster_close_on_exec(struct thread *);
int	fmaster_get_close_on_exec(struct thread *, int, bool *);
int	fmaster_set_close_on_exec(struct thread *, int, bool);
int	fmaster_get_file_status_flags(struct thread *, int, int *);
int	fmaster_set_file_status_flags(struct thread *, int, int);
int	fmaster_open(struct thread *, const char *, char *, int, mode_t);

int	fmaster_fd_of_master_fd(struct thread *, int, int *);
int	fmaster_fd_of_slave_fd(struct thread *, int, int *);

/* sockets */
int	fmaster_fix_pending_socket_to_master(struct thread *, int,
					     const char *);
int	fmaster_fix_pending_socket_to_slave(struct thread *, int, const char *);
int	fmaster_get_pending_socket(struct thread *, int,
				   struct fmaster_pending_sock *);
int	fmaster_register_pending_socket(struct thread *, int, int, int);
int	fmaster_setsockopt_pending_sock(struct thread *, int, int, int, void *,
					int);

/* protocols */
int	fmaster_connect_to_mhub(struct thread *, const char *, uint64_t, pid_t,
				int *);
int	fmaster_execute_close(struct thread *, int);
int	fmaster_execute_getdirentries(struct thread *, int, char *,
				      unsigned int, long *);
int	fmaster_execute_return_optional32(struct thread *, command_t,
					  int (*)(struct thread *, int *,
						  payload_size_t *, void *),
					  void *);
int	fmaster_execute_return_generic32(struct thread *, command_t);
int	fmaster_execute_return_generic64(struct thread *, command_t);
int	fmaster_execute_return_int32_with_token(struct thread *, command_t,
						char **, uint64_t *);
int	fmaster_execute_fcntl(struct thread *, int, int, long);
int	fmaster_execute_open(struct thread *, char *, int, mode_t);
int	fmaster_execute_setsockopt(struct thread *, int, int, int, void *, int);
int	fmaster_execute_connect_protocol(struct thread *td,
					 command_t call_command,
					 command_t return_command, int s,
					 struct sockaddr *name,
					 socklen_t namelen);
int	fmaster_execute_accept_protocol(struct thread *, command_t, command_t,
					int, struct sockaddr *, socklen_t *);
int	fmaster_execute_accept_return(struct thread *, command_t,
				      struct sockaddr *, socklen_t *);
int	fmaster_return_fd(struct thread *, short, enum fmaster_file_place, int,
			  const char *);
int	fmaster_write_command_with_empty_payload(struct thread *, command_t);

/* memory management */
void	*fmaster_malloc(struct thread *, size_t);
void	fmaster_freeall(struct thread *);

/* logging */
typedef unsigned int flag_t;

struct flag_definition {
	flag_t value;
	const char *name;
};

#define	DEFINE_FLAG(name)	{ name, #name }

void	fmaster_chain_flags(char *, size_t, flag_t, struct flag_definition[],
			    size_t);
long	fmaster_subtract_timeval(const struct timeval *,
				 const struct timeval *);
int	fmaster_openlog(struct thread *);
void	fmaster_log(struct thread *, int, const char *, ...);
void	fmaster_log_all(struct thread *, const char *, const char *, size_t);
int	fmaster_log_buf(struct thread *, const char *, const char *, size_t);
void	fmaster_log_syscall_end(struct thread *, const char *,
				const struct timeval *, int);
int	fmaster_log_msghdr(struct thread *, const char *,
			   const struct msghdr *, size_t);
const char *
	fmaster_get_sockopt_name(int);
const char *
	fmaster_str_of_place(enum fmaster_file_place);
void	_fmaster_dump_file_table(struct thread *, const char *, unsigned int);
#define	fmaster_dump_file_table(td)	do {			\
	_fmaster_dump_file_table((td), __FILE__, __LINE__);	\
} while (0)

/* anything else */
int	fmaster_is_master_file(struct thread *, const char *);

void		fmaster_abort(struct thread *, const char *, ...);
void		fmaster_schedtail(struct thread *);
int		fmaster_copyin_msghdr(struct thread *, const struct msghdr *,
				      struct msghdr *);
const char	*fmaster_geterrorname(int);
int		fmaster_do_kevent(struct thread *, const struct kevent *, int,
				  struct kevent *, int *,
				  const struct timespec *);

/* misc */
int	fmaster_copyout_sockaddr(const struct sockaddr *, socklen_t,
				 struct sockaddr *, socklen_t *);
#define	fmaster_check_connection(td)	do {			\
	__fmaster_check_connection__((td), __FILE__, __LINE__);	\
} while (0)
void	__fmaster_check_connection__(struct thread *, const char *, int);

enum fmaster_pre_execute_result {
	PRE_EXEC_END,
	PRE_EXEC_CONT
};

#define	array_sizeof(a)		(sizeof(a) / sizeof(a[0]))

MALLOC_DECLARE(M_FMASTER);

#endif

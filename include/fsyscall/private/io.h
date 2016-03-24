#if !defined(FSYSCALL_PRIVATE_IO_H_INCLUDED)
#define FSYSCALL_PRIVATE_IO_H_INCLUDED

#include <sys/types.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>

struct io {
	int	io_fd;
	int	io_error;
};

void	io_init(struct io *, int);

int	io_read_command(struct io *, command_t *);
int	io_read_int8(struct io *, int8_t *, payload_size_t *);
int	io_read_int16(struct io *, int16_t *, payload_size_t *);
int	io_read_int32(struct io *, int32_t *, payload_size_t *);
int	io_read_int64(struct io *, int64_t *, payload_size_t *);
int	io_read_payload_size(struct io *, payload_size_t *);
int	io_read_pair_id(struct io *, pair_id_t *);
int	io_read_sigset(struct io *, sigset_t *, payload_size_t *);
int	io_read_string(struct io *, char **, payload_size_t *);
int	io_read_timeval(struct io *, struct timeval *, payload_size_t *);
#define	io_read_uint8(io, n, len)	io_read_int8((io),	\
						     (int8_t *)(n), (len))
#define	io_read_uint16(io, n, len)	io_read_int16((io),	\
						      (int16_t *)(n), (len))
#define	io_read_uint32(io, n, len)	io_read_int32((io),	\
						      (int32_t *)(n), (len))
#define	io_read_uint64(io, n, len)	io_read_int64((io),	\
						      (int64_t *)(n), (len))
#define	io_read_short		io_read_int16
#define	io_read_int		io_read_int32
#define	io_read_long		io_read_int64
#define	io_read_ushort		io_read_uint16
#define	io_read_uint		io_read_uint32
#define	io_read_ulong		io_read_uint64
#define	io_read_socklen		io_read_uint32
#define	io_read_pid		io_read_int32
#define	io_read_time		io_read_int64
#define	io_read_susecond	io_read_int64
int	io_read_all(struct io *, void *, payload_size_t);
int	io_read_numeric_sequence(struct io *, char *, payload_size_t);

void		write_command(int, command_t);
void		write_int32(int, int32_t);
void		write_int64(int, int64_t);
void		write_pair_id(int, pair_id_t);
void		write_payload_size(int, payload_size_t);
#define		write_uint32(fd, n)	write_int32((fd), (int32_t)(n))
#define		write_pid(fd, pid)	write_int32((fd), (pid))
void		write_or_die(int, const void *, size_t);

int	io_transfer(struct io *, int, uint32_t);

#endif

#if !defined(FSYSCALL_PRIVATE_IO_OR_DIE_H_INCLUDED)
#define FSYSCALL_PRIVATE_IO_OR_DIE_H_INCLUDED

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <fsyscall/private/command.h>
#include <fsyscall/private/io.h>

void		read_or_die(struct io *, void *, int);
int		read_numeric_sequence(struct io *, char *, int);

int16_t		read_int16(struct io *, payload_size_t *);
int32_t		read_int32(struct io *, payload_size_t *);
int64_t		read_int64(struct io *, payload_size_t *);
uint8_t		read_uint8(struct io *, payload_size_t *);
uint16_t	read_uint16(struct io *, payload_size_t *);
uint32_t	read_uint32(struct io *, payload_size_t *);
uint64_t	read_uint64(struct io *, payload_size_t *);
short		read_short(struct io *, payload_size_t *);
int		read_int(struct io *, payload_size_t *);
long		read_long(struct io *, payload_size_t *);
unsigned short	read_ushort(struct io *, payload_size_t *);
unsigned int	read_uint(struct io *, payload_size_t *);
unsigned long	read_ulong(struct io *, payload_size_t *);
pid_t		read_pid(struct io *, payload_size_t *);
socklen_t	read_socklen(struct io *, payload_size_t *);
#if 0
time_t		read_time(struct io *, int *);
suseconds_t	read_susecond(struct io *, int *);
#endif
char *		read_string(struct io *, payload_size_t *);

command_t	read_command(struct io *);
pair_id_t	read_pair_id(struct io *);
payload_size_t	read_payload_size(struct io *);

void		read_sigset(struct io *, sigset_t *, payload_size_t *);
void		read_timeval(struct io *, struct timeval *, payload_size_t *);

void		transfer(struct io *, struct io *, uint32_t);

#define	read_mode	read_uint16

#endif

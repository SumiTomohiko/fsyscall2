#if !defined(FSYSCALL_PRIVATE_IO_OR_DIE_H_INCLUDED)
#define FSYSCALL_PRIVATE_IO_OR_DIE_H_INCLUDED

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <fsyscall/private/command.h>

void		read_or_die(int, void *, int);
int		read_numeric_sequence(int, char *, int);

int16_t		read_int16(int, payload_size_t *);
int32_t		read_int32(int, payload_size_t *);
int64_t		read_int64(int, payload_size_t *);
uint8_t		read_uint8(int, payload_size_t *);
uint16_t	read_uint16(int, payload_size_t *);
uint32_t	read_uint32(int, payload_size_t *);
uint64_t	read_uint64(int, payload_size_t *);
short		read_short(int, payload_size_t *);
int		read_int(int, payload_size_t *);
long		read_long(int, payload_size_t *);
unsigned short	read_ushort(int, payload_size_t *);
unsigned int	read_uint(int, payload_size_t *);
unsigned long	read_ulong(int, payload_size_t *);
pid_t		read_pid(int, payload_size_t *);
socklen_t	read_socklen(int, payload_size_t *);
#if 0
time_t		read_time(int, int *);
suseconds_t	read_susecond(int, int *);
#endif
char *		read_string(int, payload_size_t *);

command_t	read_command(int);
pair_id_t	read_pair_id(int);
payload_size_t	read_payload_size(int);

void		read_sigset(int, sigset_t *, payload_size_t *);
void		read_timeval(int, struct timeval *, payload_size_t *);

void		transfer(int, int, uint32_t);

#define	read_mode	read_uint16

#endif

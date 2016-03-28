#if !defined(FSYSCALL_PRIVATE_IO_OR_DIE_H_INCLUDED)
#define FSYSCALL_PRIVATE_IO_OR_DIE_H_INCLUDED

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <fsyscall/private/command.h>

void		read_or_die(int, void *, int);
int		read_numeric_sequence(int, char *, int);

int16_t		read_int16(int, int *);
int32_t		read_int32(int, int *);
int64_t		read_int64(int, int *);
uint8_t		read_uint8(int, int *);
uint32_t	read_uint32(int, int *);
uint64_t	read_uint64(int, int *);
short		read_short(int, int *);
int		read_int(int, int *);
long		read_long(int, int *);
unsigned short	read_ushort(int, int *);
unsigned int	read_uint(int, int *);
unsigned long	read_ulong(int, int *);
pid_t		read_pid(int, int *);
socklen_t	read_socklen(int, int *);
#if 0
time_t		read_time(int, int *);
suseconds_t	read_susecond(int, int *);
#endif
char *		read_string(int, uint64_t *);

command_t	read_command(int);
pair_id_t	read_pair_id(int);
payload_size_t	read_payload_size(int);

void		read_sigset(int, sigset_t *, int *);
void		read_timeval(int, struct timeval *, int *);

void		transfer(int, int, uint32_t);

#endif

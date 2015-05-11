#if !defined(FSYSCALL_PRIVATE_IO_H_INCLUDED)
#define FSYSCALL_PRIVATE_IO_H_INCLUDED

#include <sys/types.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>

command_t	read_command(int);
int8_t		read_int8(int, int *);
int16_t		read_int16(int, int *);
int32_t		read_int32(int, int *);
int64_t		read_int64(int, int *);
payload_size_t	read_payload_size(int);
pair_id_t	read_pair_id(int);
char *		read_string(int, uint64_t *);
#define		read_uint8(fd, len)	((uint8_t)read_int8((fd), (len)))
#define		read_uint16(fd, len)	((uint16_t)read_int16((fd), (len)))
#define		read_uint32(fd, len)	((uint32_t)read_int32((fd), (len)))
#define		read_uint64(fd, len)	((uint64_t)read_int64((fd), (len)))
#define		read_short		read_int16
#define		read_int		read_int32
#define		read_long		read_int64
#define		read_ushort		read_uint16
#define		read_uint		read_uint32
#define		read_ulong		read_uint64
#define		read_socklen		read_uint32
#define		read_pid		read_int32
void		read_or_die(int, const void *, size_t);
int		read_numeric_sequence(int, char *, int);

void		write_command(int, command_t);
void		write_int32(int, int32_t);
void		write_int64(int, int64_t);
void		write_pair_id(int, pair_id_t);
void		write_payload_size(int, payload_size_t);
#define		write_uint32(fd, n)	write_int32((fd), (int32_t)(n))
#define		write_pid(fd, pid)	write_int32((fd), (pid))
void		write_or_die(int, const void *, size_t);

void		transfer(int, int, uint32_t);

#endif

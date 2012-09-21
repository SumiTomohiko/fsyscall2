#if !defined(FSYSCALL_PRIVATE_IO_H_INCLUDED)
#define FSYSCALL_PRIVATE_IO_H_INCLUDED

#include <sys/types.h>

#include <fsyscall/private/command.h>

command_t	read_command(int);
int32_t		read_int32(int);
int64_t		read_int64(int);
pid_t		read_pid(int);
#define		read_uint32(fd)		((uint32_t)read_int32((fd)))
#define		read_uint64(fd)		((uint64_t)read_int64((fd)))
#define		read_payload_size	read_uint32
void		read_or_die(int, const void *, size_t);
int		read_numeric_sequence(int, char *, int);

void		write_command(int, command_t);
void		write_int32(int, int32_t);
void		write_int64(int, int64_t);
void		write_pid(int, pid_t);
#define		write_uint32(fd, n)	write_int32((fd), (int32_t)(n))
#define		write_payload_size	write_uint32
void		write_or_die(int, const void *, size_t);

void		transfer(int, int, uint32_t);

#endif

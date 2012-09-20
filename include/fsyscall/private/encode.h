#if !defined(FSYSCALL_ENCODE_H_INCLUDED)
#define FSYSCALL_ENCODE_H_INCLUDED

#include <sys/types.h>

#include <fsyscall/private/command.h>

command_t	fsyscall_decode_command(char *, int);
int32_t		fsyscall_decode_int32(char *, int);
int64_t		fsyscall_decode_int64(char *, int);
uint32_t	fsyscall_decode_uint32(char *, int);

#define		fsyscall_decode_uint32(buf, bufsize) \
	((uint32_t)fsyscall_decode_int32(buf, bufsize))

#define		fsyscall_encode_command	fsyscall_encode_uint32
int		fsyscall_encode_int32(int32_t, char *, int);
int		fsyscall_encode_int64(int64_t, char *, int);
int		fsyscall_encode_uint32(uint32_t, char *, int);

#define	FSYSCALL_BUFSIZE(type)		(sizeof(type) * 8 / 7 + 1)
#define	FSYSCALL_BUFSIZE_COMMAND	FSYSCALL_BUFSIZE(command_t)
#define	FSYSCALL_BUFSIZE_INT32		FSYSCALL_BUFSIZE(int32_t)
#define	FSYSCALL_BUFSIZE_INT64		FSYSCALL_BUFSIZE(int64_t)
#define	FSYSCALL_BUFSIZE_UINT32		FSYSCALL_BUFSIZE(uint32_t)

#endif

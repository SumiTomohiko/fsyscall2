#if !defined(FSYSCALL_ENCODE_H_INCLUDED)
#define FSYSCALL_ENCODE_H_INCLUDED

#include <sys/types.h>

#include <fsyscall/private/command.h>

int	fsyscall_decode_command(char *, int, command_t *);
int	fsyscall_decode_int8(char *, int, int8_t *);
int	fsyscall_decode_int16(char *, int, int16_t *);
int	fsyscall_decode_int32(char *, int, int32_t *);
int	fsyscall_decode_int64(char *, int, int64_t *);
#define	fsyscall_decode_uint32(buf, bufsize, dest) \
		fsyscall_decode_int32((buf), (bufsize), (int32_t *)(dest))

#define		fsyscall_encode_command	fsyscall_encode_uint32
int		fsyscall_encode_int32(int32_t, char *, int);
int		fsyscall_encode_int64(int64_t, char *, int);
int		fsyscall_encode_uint8(uint8_t, char *, int);
int		fsyscall_encode_uint16(uint16_t, char *, int);
int		fsyscall_encode_uint32(uint32_t, char *, int);
int		fsyscall_encode_uint64(uint64_t, char *, int);

#define	FSYSCALL_BUFSIZE(type)		(sizeof(type) * 8 / 7 + 1)
#define	FSYSCALL_BUFSIZE_COMMAND	FSYSCALL_BUFSIZE(command_t)
#define	FSYSCALL_BUFSIZE_INT8		FSYSCALL_BUFSIZE(int8_t)
#define	FSYSCALL_BUFSIZE_INT16		FSYSCALL_BUFSIZE(int16_t)
#define	FSYSCALL_BUFSIZE_INT32		FSYSCALL_BUFSIZE(int32_t)
#define	FSYSCALL_BUFSIZE_INT64		FSYSCALL_BUFSIZE(int64_t)
#define	FSYSCALL_BUFSIZE_PAYLOAD_SIZE	FSYSCALL_BUFSIZE(payload_size_t)
#define	FSYSCALL_BUFSIZE_UINT8		FSYSCALL_BUFSIZE(uint8_t)
#define	FSYSCALL_BUFSIZE_UINT16		FSYSCALL_BUFSIZE(uint16_t)
#define	FSYSCALL_BUFSIZE_UINT32		FSYSCALL_BUFSIZE(uint32_t)
#define	FSYSCALL_BUFSIZE_UINT64		FSYSCALL_BUFSIZE(uint64_t)

#if !defined(KLD_MODULE)
#define		encode_command	encode_uint32
int		encode_int32(int32_t, char *, int);
int		encode_int64(int64_t, char *, int);
int		encode_uint16(uint16_t, char *, int);
int		encode_uint32(uint32_t, char *, int);
int		encode_uint64(uint64_t, char *, int);
command_t	decode_command(char *, int);
int8_t		decode_int8(char *, int);
int32_t		decode_int32(char *, int);
int64_t		decode_int64(char *, int);
#define		decode_payload_size(buf, bufsize) \
			(payload_size_t)decode_uint32((buf), (bufsize))
#define		decode_uint32(buf, bufsize) \
			(uint32_t)decode_int32((buf), (bufsize))
#endif	/* !KLD_MODULE */

#endif

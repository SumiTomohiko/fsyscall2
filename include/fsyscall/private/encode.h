#if !defined(FSYSCALL_ENCODE_H_INCLUDED)
#define FSYSCALL_ENCODE_H_INCLUDED

#include <sys/types.h>

int fsyscall_decode_int(char *, int);
int fsyscall_decode_int32(char *, int32_t);
int fsyscall_encode_int(int, char *, int);
int fsyscall_encode_int32(int32_t, char *, int);
int fsyscall_encode_uint(unsigned int, char *, int);
int fsyscall_encode_uint32(uint32_t, char *, int);

#define	FSYSCALL_BUFSIZE(type)	(sizeof(type) * 8 / 7 + 1)
#define	FSYSCALL_BUFSIZE_INT	FSYSCALL_BUFSIZE(int)
#define	FSYSCALL_BUFSIZE_INT32	FSYSCALL_BUFSIZE(int32_t)
#define	FSYSCALL_BUFSIZE_UINT	FSYSCALL_BUFSIZE(unsigned int)

#endif

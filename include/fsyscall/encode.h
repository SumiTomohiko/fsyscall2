#if !defined(FSYSCALL_ENCODE_H_INCLUDED)
#define FSYSCALL_ENCODE_H_INCLUDED

int fsyscall_encode_int(int, char *, int);
int fsyscall_encode_uint(unsigned int, char *, int);

#define	FSYSCALL_BUFSIZE(type)	(sizeof(type) * 8 / 7 + 1)
#define	FSYSCALL_BUFSIZE_INT	FSYSCALL_BUFSIZE(int)
#define	FSYSCALL_BUFSIZE_UINT	FSYSCALL_BUFSIZE(unsigned int)

#endif

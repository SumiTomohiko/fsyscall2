#if !defined(FSYSCALL_ENCODE_H_INCLUDED)
#define FSYSCALL_ENCODE_H_INCLUDED

int fsyscall_encode_uint(unsigned int, char *, int);

#define	FSYSCALL_BUFSIZE_UINT	(32 / 7 + 1)

#endif

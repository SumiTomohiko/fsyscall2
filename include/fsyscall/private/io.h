#if !defined(FSYSCALL_PRIVATE_IO_H_INCLUDED)
#define FSYSCALL_PRIVATE_IO_H_INCLUDED

#include <sys/types.h>

void read_or_die(int, const void *, size_t);
void send_int(int, int);
void write_or_die(int, const void *, size_t);

#endif

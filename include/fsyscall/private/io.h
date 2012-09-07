#if !defined(FSYSCALL_PRIVATE_IO_H_INCLUDED)
#define FSYSCALL_PRIVATE_IO_H_INCLUDED

#include <sys/types.h>

int32_t read_int32(int);
pid_t read_pid(int);
void read_or_die(int, const void *, size_t);
void write_int(int, int);
void write_int32(int, int32_t);
void write_or_die(int, const void *, size_t);
void write_pid(int, pid_t);

#endif

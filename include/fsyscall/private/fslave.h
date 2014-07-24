#if !defined(FSYSCALL_PRIVATE_FSLAVE_H_INCLUDED)
#define FSYSCALL_PRIVATE_FSLAVE_H_INCLUDED

#include <fsyscall/private/command.h>

struct slave {
	int rfd;
	int wfd;
	const char *sock_path;
};

void die_if_payload_size_mismatched(int, int);
void return_int(struct slave *, command_t, int, int);
void return_ssize(struct slave *, command_t, ssize_t, int);

#endif

#if !defined(FSYSCALL_PRIVATE_HUB_H_INCLUDED)
#define FSYSCALL_PRIVATE_HUB_H_INCLUDED

struct connection {
	int rfd;
	int wfd;
};

void transport_fds(int, int);

#endif

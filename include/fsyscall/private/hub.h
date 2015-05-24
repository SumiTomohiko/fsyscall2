#if !defined(FSYSCALL_PRIVATE_HUB_H_INCLUDED)
#define FSYSCALL_PRIVATE_HUB_H_INCLUDED

#include <sys/types.h>

struct connection {
	int rfd;
	int wfd;
};

int	hub_open_fork_socket(const char *);
void	hub_close_fork_socket(int);
void	hub_generate_token(char *, size_t);
void	hub_close_fds_or_die(int, int);
void	hub_unlink_socket(const char *);
void transport_fds(int, int);

#endif

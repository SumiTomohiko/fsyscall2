#if !defined(FSYSCALL_PRIVATE_HUB_H_INCLUDED)
#define FSYSCALL_PRIVATE_HUB_H_INCLUDED

#include <sys/types.h>

#include <fsyscall/private/hub.h>
#include <fsyscall/private/io.h>

struct connection {
	struct io	*conn_io;
};

int	hub_open_fork_socket(const char *);
void	hub_close_fork_socket(int);
void	hub_generate_token(char *, size_t);
void	hub_close_fds_or_die(struct io *);
void	hub_unlink_socket(const char *);
void	transport_fds(struct io *, struct io *);

#define	KEEPALIVE_INTERVAL	60		/* [sec] */
#define	ABORT_SEC		(4 * 60)	/* [sec] */

#endif

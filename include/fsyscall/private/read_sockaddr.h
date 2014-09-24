#if !defined(FSYSCALL_PRIVATE_READ_SOCKADDR_H_INCLUDED)
#define	FSYSCALL_PRIVATE_READ_SOCKADDR_H_INCLUDED

#include <sys/socket.h>
#include <sys/types.h>

struct rsopts {
	void	*rs_bonus;
	int	(*rs_read_socklen)(struct rsopts *, socklen_t *, int *);
	int	(*rs_read_uint8)(struct rsopts *, uint8_t *, int *);
	int	(*rs_read_uint64)(struct rsopts *, uint64_t *, int *);
	int	(*rs_read)(struct rsopts *, char *, int);
	void	*(*rs_malloc)(struct rsopts *, size_t);
	void	(*rs_free)(struct rsopts *, void *);
};

int	fsyscall_read_sockaddr(struct rsopts *, struct sockaddr_storage *,
			       int *);

#endif

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <fsyscall/private/close_or_die.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/io_or_die.h>

void
transport_fds(struct io *src, struct io *dst)
{
	payload_size_t _;
	int n;
	char *buf;

	n = read_int32(src, &_);
	assert(0 <= n);
	buf = (char *)alloca(sizeof(char) * n);
	read_or_die(src, buf, n);

	write_int32(dst, n);
	write_or_die(dst, buf, n);
}

int
hub_open_fork_socket(const char *path)
{
	struct sockaddr_storage sockaddr;
	struct sockaddr_un *paddr = (struct sockaddr_un *)&sockaddr;
	socklen_t optlen;
	int optval, sock;

	unlink(path);
	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		die(1, "socket(2) failed");
	optval = 1;
	optlen = sizeof(optval);
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, optlen) == -1)
		die(1, "setsockopt(2) failed");
	paddr->sun_len = sizeof(sockaddr);
	paddr->sun_family = AF_LOCAL;
	strcpy(paddr->sun_path, path);
	if (bind(sock, (struct sockaddr *)paddr, SUN_LEN(paddr)) != 0)
		die(1, "bind(2) failed");
	if (listen(sock, 0) != 0)
		die(1, "listen(2) failed");

	return (sock);
}

void
hub_close_fork_socket(int sock)
{
	close_or_die(sock);
}

void
hub_unlink_socket(const char *path)
{

	if (unlink(path) == -1)
		warn("cannot remove the socket: %s", path);
}

static char
generate_printable()
{
	char c = 0;

	while (!isprint(c))
		c = arc4random_uniform(128);

	return (c);
}

void
hub_generate_token(char *token, size_t size)
{
	int i;

	for (i = 0; i < size; i++)
		token[i] = generate_printable();
}

void
hub_close_fds_or_die(struct io *io)
{

	if (io_close(io) == -1)
		diec(1, io->io_error, "cannot close");
}

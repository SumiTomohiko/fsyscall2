#if !defined(TINY_RUNTIME_H_INCLUDED)
#define TINY_RUNTIME_H_INCLUDED

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

void	print_num(long);

#endif

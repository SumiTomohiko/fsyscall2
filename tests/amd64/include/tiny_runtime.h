#if !defined(TINY_RUNTIME_H_INCLUDED)
#define TINY_RUNTIME_H_INCLUDED

#include <sys/types.h>
#include <sys/event.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

int	isspace(int);

void	tr_print_num(long);
void	tr_print_str(const char *);
#define	print_num	tr_print_num

typedef int (*tr_accept_callback)(int, struct sockaddr *, socklen_t);
typedef	int (*tr_chdir_callback)(const char *);
typedef int (*tr_connect_callback)(int);
int	tr_run_chdir_x_test(int, const char *[], tr_chdir_callback);
int	tr_run_client_server(const char *, tr_accept_callback,
			     tr_connect_callback);

int	tr_run_dup2_closed2x_test(int);
int	tr_run_dup2_master2x_test(int);
int	tr_run_dup2_slave2x_test(int, const char *);

int	tr_wait_data(int);

#define	array_sizeof(a)	(sizeof(a) / sizeof(a[0]))

#endif

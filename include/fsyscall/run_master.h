#if !defined(FSYSCALL_RUN_MASTER_H_INCLUDED)
#define FSYSCALL_RUN_MASTER_H_INCLUDED

#include <openssl/ssl.h>

int	fsyscall_run_master_nossl(int, int, int, char * const *,
				  char * const *);
int	fsyscall_run_master_ssl(SSL *, int, char *, char * const *,
				char * const *);

#endif

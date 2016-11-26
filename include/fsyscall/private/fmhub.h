#if !defined(FSYSCALL_PRIVATE_FMHUB_H)
#define FSYSCALL_PRIVATE_FMHUB_H

#include <openssl/ssl.h>

int	fmhub_run_nossl(int, int, int, char * const *, char * const *,
			const char *);
int	fmhub_run_ssl(SSL *, int, char * const *, char * const *, const char *);

#endif

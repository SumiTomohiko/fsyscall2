#include <sys/param.h>
#include <stdio.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <fsyscall/private/fmhub.h>

static void
get_fork_sock(char *buf, size_t bufsize)
{

	snprintf(buf, bufsize, "/tmp/fmhub.%d", getpid());
}

int
fsyscall_run_master_nossl(int shub2mhub, int mhub2shub, int argc,
			  char *const argv[], char *const envp[])
{
	int retval;
	char fork_sock[MAXPATHLEN];

	get_fork_sock(fork_sock, sizeof(fork_sock));
	retval = fmhub_run_nossl(shub2mhub, mhub2shub, argc, argv, envp,
				 fork_sock);

	return (retval);
}

int
fsyscall_run_master_ssl(SSL *ssl, int argc, char *const argv[],
			char *const envp[])
{
	int retval;
	char fork_sock[MAXPATHLEN];

	get_fork_sock(fork_sock, sizeof(fork_sock));
	retval = fmhub_run_ssl(ssl, argc, argv, envp, fork_sock);

	return (retval);
}

#include <sys/param.h>
#include <stdio.h>
#include <unistd.h>

#include <fsyscall/private/fmhub.h>

int
fsyscall_run_master(int shub2mhub, int mhub2shub, int argc, char *const argv[],
		    char *const envp[])
{
	int retval;
	char fork_sock[MAXPATHLEN];

	snprintf(fork_sock, sizeof(fork_sock), "/tmp/fmhub.%d", getpid());
	retval = fmhub_run(shub2mhub, mhub2shub, argc, argv, envp, fork_sock);

	return (retval);
}

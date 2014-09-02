#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fsyscall/private/die.h>
#include <fsyscall/private/start.h>

static int
count_env(char *const envp[])
{
	int n = 0;
	char *const *p;

	for (p = envp; *p != NULL; p++)
		n++;

	return (n);
}

void
fsyscall_start_master(int shub2mhub, int mhub2shub, int argc, char* argv[], char* const envp[])
{
	int i, nenv, offset;
	char **args, *file, fork_sock[MAXPATHLEN], *opt_env, path[MAXPATHLEN];

	file = "fmhub";
	snprintf(path, sizeof(path), "/usr/local/bin/%s", file);
	nenv = count_env(envp);
	snprintf(fork_sock, sizeof(fork_sock), "/tmp/fmhub.%d", getpid());

	args = (char**)alloca(sizeof(char*) * (argc + 2 * nenv + 5));
	args[0] = file;

	opt_env = "--env";
	for (i = 0; i < nenv; i++) {
		args[1 + 2 * i] = opt_env;
		args[1 + 2 * i + 1] = envp[i];
	}

	offset = 1 + 2 * nenv;
	ALLOC_FD(args[offset], shub2mhub);
	ALLOC_FD(args[offset + 1], mhub2shub);
	args[offset + 2] = fork_sock;
	for (i = 0; i < argc; i++)
		args[offset + 3 + i] = argv[i];
	args[offset + 3 + i] = NULL;

	execv(path, args);
	die(-1, "cannot execv %s", path);
	/* NOTREACHED */
}

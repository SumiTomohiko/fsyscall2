#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fsyscall/private.h>

void
fsyscall_start_master(int shub2mhub, int mhub2shub, int argc, char* argv[])
{
	int i;
	char **args;

	args = (char**)alloca(sizeof(char*) * (argc + 4));
	args[0] = "fmhub";
	ALLOC_FD(args[1], shub2mhub);
	ALLOC_FD(args[2], mhub2shub);
	for (i = 0; i < argc; i++)
		args[3 + i] = argv[i];
	args[3 + i] = NULL;

	execvp(args[0], args);
	err(-1, "Cannot execvp %s", args[0]);
	/* NOTREACHED */
}

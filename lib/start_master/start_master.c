#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <fsyscall/private/die.h>
#include <fsyscall/private/start.h>

void
fsyscall_start_master(int shub2mhub, int mhub2shub, int argc, char* argv[])
{
	int i;
	char **args, *file, path[MAXPATHLEN];

	file = "fmhub";

	snprintf(path, sizeof(path), "/usr/local/bin/%s", file);

	args = (char**)alloca(sizeof(char*) * (argc + 4));
	args[0] = file;
	ALLOC_FD(args[1], shub2mhub);
	ALLOC_FD(args[2], mhub2shub);
	for (i = 0; i < argc; i++)
		args[3 + i] = argv[i];
	args[3 + i] = NULL;

	execv(path, args);
	die(-1, "cannot execv %s", path);
	/* NOTREACHED */
}

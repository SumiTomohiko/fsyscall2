#include <tiny_runtime.h>

/*
 * clang requested memset(3).
 */
void *
memset(void *b, int c, size_t len)
{
	size_t i;
	char *p = (char *)b;

	for (i = 0; i < len; i++)
		p[i] = c;

	return (b);
}

int
main(int argc, const char *argv[])
{
	char *args[] = { "/usr/bin/true", NULL }, *envp[] = { NULL };

	execve(args[0], args, envp);
	/* NOTREACHED */

	return (1);
}

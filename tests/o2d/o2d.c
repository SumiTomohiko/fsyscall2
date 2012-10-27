#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, const char *argv[])
{
	long d;
	char *endptr;

	d = strtol(argv[1], &endptr, 8);
	if (*endptr != '\0')
		return (1);
	printf("%ld", d);

	return (0);
}

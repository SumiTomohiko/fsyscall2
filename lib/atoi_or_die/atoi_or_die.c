#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int
atoi_or_die(const char *s, const char *name)
{
	char *endptr;
	int base = 10;
	int n = strtol(s, &endptr, base);

	if (*endptr != '\0') {
		printf("%s must be an integer.\n", name);
		exit(-1);
	}
	return (n);
}

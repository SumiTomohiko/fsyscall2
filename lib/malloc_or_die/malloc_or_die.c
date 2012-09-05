#include <err.h>
#include <stdlib.h>

void *
malloc_or_die(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL)
		err(-1, "Cannot allocate memory");
	return (ptr);
}

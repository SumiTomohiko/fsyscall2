#include <stdlib.h>

#include <fsyscall/private/die.h>

void *
malloc_or_die(size_t size)
{
	void *ptr = malloc(size);
	if (ptr == NULL)
		die(-1, "Cannot allocate memory");
	return (ptr);
}

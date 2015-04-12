#include <ctype.h>
#include <stdio.h>

int
main()
{
	int c;

	while ((c = fgetc(stdin)) != EOF)
		fputc(isprint(c) || (c == '\n') ? c : ' ', stdout);

	return (0);
}

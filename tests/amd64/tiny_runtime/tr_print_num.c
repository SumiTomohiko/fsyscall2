#include <tiny_runtime.h>

void
tr_print_num(long n)
{
	long l, m;
	const char digits[] = "0123456789";
	char buf[32], *p;

	p = &buf[sizeof(buf) - 1];
	*p = '\0';

	m = n;
	do {
		p--;
		*p = digits[m % 10];
		m /= 10;
	} while (0 < m);

	tr_print_str(p);
}

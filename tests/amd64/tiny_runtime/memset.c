
void *
memset(void *b, int c, size_t len)
{
	size_t i;
	unsigned char datum, *p;

	datum = (unsigned char)c;
	p = (unsigned char *)b;
	for (i = 0; i < len; i++)
		p[i] = datum;

	return (b);
}

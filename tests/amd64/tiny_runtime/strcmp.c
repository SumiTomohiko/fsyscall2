
int
strcmp(const char *s1, const char *s2)
{
	const unsigned char *p, *q;

	for (p = (unsigned char *)s1, q = (unsigned char *)s2;
	     ((*p - *q) == 0) && (*p != '\0') && (*q != '\0');
	     p++, q++)
		;

	return (*p - *q);
}

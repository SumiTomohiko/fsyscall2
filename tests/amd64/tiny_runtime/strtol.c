
static char tab[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35 };

long
strtol(const char *nptr, char **endptr, int base)
{
	long m, n;
	int sign;
	const char *p;
	char c;

	if (nptr == NULL) {
		errno = EINVAL;
		return (0);
	}
	for (p = nptr; isspace(*p); p++)
		;
	switch (*p) {
	case '-':
		sign = -1;
		p++;
		break;
	case '+':
		p++;
		/* FALLTHROUGH */
	default:
		sign = 1;
		break;
	}

	n = 0;
	for (/* nothing */; (c = *p) != '\0'; p++) {
		if ((c < 0) || (sizeof(tab) <= c))
			break;
		m = tab[c];
		if ((m == -1) || (base <= m))
			break;
		n = base * n + m;
	}
	if (endptr != NULL)
		*endptr = (char *)p;

	return (sign * n);
}

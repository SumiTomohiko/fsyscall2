
static char tab[] = {
	0, 0, 0, 0, 0, 0, 0, 0,
	1, 1, 1, 1, 1, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	1 };

int
isspace(int c)
{

	return ((c < 0) || (sizeof(tab) <= c) ? 0 : tab[c]);
}

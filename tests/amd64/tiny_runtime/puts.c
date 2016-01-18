
int
puts(const char *str)
{
	int fd = 1;
	const char *p;
	char newline = '\n';

	for (p = str; *p != '\0'; p++)
		write(fd, p, sizeof(*p));
	write(fd, &newline, sizeof(newline));

	return (42);
}

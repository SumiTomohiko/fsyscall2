
int
main(int argc, const char *argv[])
{
	struct stat sb;
	const char *path = "/tmp";

	if (stat(path, &sb) != 0)
		return (2);

	return (S_ISDIR(sb.st_mode) ? 0 : 3);
}

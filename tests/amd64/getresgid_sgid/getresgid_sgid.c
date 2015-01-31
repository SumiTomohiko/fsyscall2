
int
main(int argc, const char *argv[])
{
	gid_t gid;

	return (getresgid(NULL, NULL, &gid) == 0 ? 0 : 1);
}

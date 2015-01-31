
int
main(int argc, const char *argv[])
{
	gid_t gid;

	return (getresgid(NULL, &gid, NULL) == 0 ? 0 : 1);
}

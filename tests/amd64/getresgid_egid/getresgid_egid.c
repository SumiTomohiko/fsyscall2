
int
main(int argc, const char *argv[])
{
	gid_t gid;

	return (getresgid(&gid, NULL, NULL) == 0 ? 0 : 1);
}

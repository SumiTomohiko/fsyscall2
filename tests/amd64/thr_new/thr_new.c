
static void *
start_routine(void *unused)
{

	return (NULL);
}

int
main(int argc, const char *argv[])
{
	pthread_t thread;
	int error;
	void *value;

	error = pthread_create(&thread, NULL, start_routine, NULL);
	if (error != 0)
		return (error);
	error = pthread_join(thread, &value);
	if (error != 0)
		return (error);

	return (0);
}

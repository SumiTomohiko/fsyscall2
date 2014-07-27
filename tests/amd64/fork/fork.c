#include <tiny_runtime.h>

int
main(int argc, const char *argv[])
{
	pid_t pid;
	const char *msg = "FORK OK";

	pid = fork();
	switch (pid) {
	case -1:
		return (1);
	case 0:
		write(1, msg, strlen(msg));
		break;
	default:
		break;
	}

	return (0);
}

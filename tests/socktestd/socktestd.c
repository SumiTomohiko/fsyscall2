#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

static void
die_stderr(const char *msg, ...)
{
	va_list ap;
	int e;
	char buf[8192];

	e = errno;

	va_start(ap, msg);
	vsnprintf(buf, sizeof(buf), msg, ap);
	va_end(ap);

	fprintf(stderr, "died: %s: %s\n", buf, strerror(e));
	exit(1);
}

static void
die_syslog(const char *msg, ...)
{
	va_list ap;
	int e;
	char buf[8192];

	e = errno;

	va_start(ap, msg);
	vsnprintf(buf, sizeof(buf), msg, ap);
	va_end(ap);

	syslog(LOG_ERR, "died: %s: %s\n", buf, strerror(e));
	exit(1);
}

static void (*die)(const char *, ...) = die_stderr;

static void
usage()
{

	fprintf(stderr,
		"usage: %s --socket-file=/path/to/socket --pid-file=/path/to/pi"
		"d\n",
		getprogname());
	exit(2);
}

static void
write_pid_file(const char *path)
{
	FILE *fp;
	char buf[8192];

	fp = fopen(path, "w");
	if (fp == NULL)
		die("Cannot open %s", path);
	snprintf(buf, sizeof(buf), "%d", getpid());
	fputs(buf, fp);
	fclose(fp);
}

static bool terminated = false;

static void
sigterm_handler(int sig)
{

	terminated = true;
}

static bool
wait_connection(int fd)
{
	fd_set fds;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	return (select(fd + 1, &fds, NULL, NULL, NULL) == 1);
}

int
main(int argc, char *argv[])
{
	struct sockaddr_un *psa;
	struct sockaddr_storage addr, sockaddr;
	struct sockaddr *paddr;
	struct option longopts[] = {
		{ "pid-file", required_argument, NULL, 'p' },
		{ "socket-file", required_argument, NULL, 's' },
		{ 0, 0, 0, 0 }
	};
	FILE *fp;
	socklen_t addrlen, len;
	int opt, s, sock;
	char buf[8192], pid_file[8192], socket_file[8192];

	pid_file[0] = socket_file[0] = '\0';
	while ((opt = getopt_long(argc, argv, "+", longopts, NULL)) != -1)
		switch (opt) {
		case 'p':
			strncpy(pid_file, optarg, sizeof(pid_file));
			break;
		case 's':
			strncpy(socket_file, optarg, sizeof(socket_file));
			break;
		case '?':
		default:
			fprintf(stderr, "Unknown option\n");
			exit(2);
		}
	if (strlen(pid_file) == 0) {
		fprintf(stderr, "No pid path given\n");
		usage();
	}
	if (strlen(socket_file) == 0) {
		fprintf(stderr, "No socket path given\n");
		usage();
	}

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		die("socket(2) failed");
	psa = (struct sockaddr_un *)&sockaddr;
	psa->sun_len = sizeof(sockaddr);
	psa->sun_family = AF_LOCAL;
	strncpy(psa->sun_path, socket_file, sizeof(psa->sun_path));
	addrlen = sizeof(psa->sun_len) + sizeof(psa->sun_family) + strlen(socket_file);
	if (bind(sock, (struct sockaddr *)psa, addrlen) != 0)
		die("bind(2) failed");
	if (listen(sock, 8192) != 0)
		die("listen(2) failed");
	if (daemon(1, 1) != 0)
		die("daemon(3) failed");
	openlog(basename(argv[0]), LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "started: %s", socket_file);
	die = die_syslog;
	write_pid_file(pid_file);
	signal(SIGTERM, sigterm_handler);

	paddr = (struct sockaddr *)&addr;
	while (wait_connection(sock)) {
		s = accept(sock, paddr, &len);
		if (s == -1)
			die("accept(2) failed");
		syslog(LOG_INFO, "accepted a client.");
		fp = fdopen(s, "r");
		if (fp == NULL)
			die("fdopen(3) failed");
		while (fgets(buf, sizeof(buf), fp) != NULL) {
			/*
			 * Does nothing.
			 */
		}
		if (ferror(fp) != 0)
			die("fgets(3) failed");
		if (fclose(fp) != 0)
			die("fclose(3) for client failed");
		syslog(LOG_INFO, "closed the client.");
	}

	if (close(sock) != 0)
		die("close(2) for daemon failed");
	if (unlink(socket_file) != 0)
		die("unlink(2) failed: %s", socket_file);
	if (unlink(pid_file) != 0)
		die("unlink(2) failed: %s", pid_file);
	syslog(LOG_INFO, "terminated.");
	closelog();

	return (0);
}

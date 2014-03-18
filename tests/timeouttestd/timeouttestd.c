#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

static void
die(const char *fmt, ...)
{
	va_list ap;
	int e;
	char buf[1024], buf2[1024];

	e = errno;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	snprintf(buf2, sizeof(buf2), "%s: %s", buf, strerror(e));

	syslog(LOG_ERR, "%s", buf2);
	fprintf(stderr, "%s\n", buf2);

	exit(1);
}

static void
usage()
{
	printf("usage: %s --fifo-file /path/to/fifo --pid-file /path/to/pid\n",
	       getprogname());
}

static void
write_pid_file(const char *path)
{
	FILE *fp;

	fp = fopen(path, "w");
	if (fp == NULL)
		die("can't open %s", path);
	fprintf(fp, "%ld", getpid());
	fclose(fp);
}

static bool terminated = false;

static void
handle_sigterm(int sig)
{
	terminated = true;
}

int
main(int argc, char *argv[])
{
	FILE *fp;
	struct option longopts[] = {
		{ "fifo-file", required_argument, NULL, 'f' },
		{ "pid-file", required_argument, NULL, 'p' },
		{ 0, 0, 0, 0 }
	};
	struct timespec t;
	int opt;
	const char *fifofile, *pidfile;

	fifofile = pidfile = "";
	while ((opt = getopt_long(argc, argv, "+", longopts, NULL)) != -1)
		switch (opt) {
		case 'f':
			fifofile = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case '+':
		default:
			usage();
			return (1);
		}
	if (strlen(fifofile) == 0) {
		fprintf(stderr, "No fifo path given.\n");
		return (2);
	}
	if (strlen(pidfile) == 0) {
		fprintf(stderr, "No pid path given.\n");
		return (3);
	}
	openlog(getprogname(), LOG_PID, LOG_LOCAL0);
	syslog(LOG_INFO, "started.");

	if (daemon(1, 1) != 0)
		die("can't daemon(3)");
	if (signal(SIGTERM, handle_sigterm) == SIG_ERR)
		die("can't signal(2)");
	write_pid_file(pidfile);

	fp = fopen(fifofile, "w");
	if (fp == NULL)
		die("can't fopen(3): %s", fifofile);
	syslog(LOG_INFO, "opened: %s", fifofile);
	t.tv_sec = 0;
	t.tv_nsec = 100000;	/* 100[msec] */
	while (!terminated)
		nanosleep(&t, NULL);
	fclose(fp);

	syslog(LOG_INFO, "terminated.");
	closelog();

	return (0);
}

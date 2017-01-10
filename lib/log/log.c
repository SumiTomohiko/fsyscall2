#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#include <fsyscall/private.h>

void
log_graceful_exit2(int status, void (*f)(int, const char *msg))
{
	char buf[8192];

	snprintf(buf, sizeof(buf), "exited gracefully with status %d.", status);
	f(LOG_INFO, buf);
}

static void
do_syslog(int priority, const char *msg)
{

	syslog(priority, "%s", msg);
}

void
log_graceful_exit(int status)
{

	log_graceful_exit2(status, do_syslog);
}

void
log_start_message2(int argc, char *const argv[], void (*f)(int, const char *))
{
	int i;
	char buf[4096], buf2[4096], *p, *pend, *s;

	pend = buf + array_sizeof(buf);
	p = buf;
	for (i = 0; (i < argc) && (p < pend); i++) {
		*p = ' ';

		s = argv[i];
		strncpy(p + 1, s, pend - p - 1);
		p += strlen(s) + 1;
	}
	p[0] = '\0';

	snprintf(buf2, sizeof(buf2), "started:%s", buf);
	f(LOG_INFO, buf2);
}

void
log_start_message(int argc, char *const argv[])
{

	log_start_message2(argc, argv, do_syslog);
}

#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#include <fsyscall/private.h>

void
log_start_message(int argc, char *argv[])
{
	int i;
	char buf[4096], *p, *pend, *s;

	pend = buf + array_sizeof(buf);
	p = buf;
	for (i = 0; (i < argc) && (p < pend); i++) {
		*p = ' ';

		s = argv[i];
		strncpy(p + 1, s, pend - p - 1);
		p += strlen(s) + 1;
	}
	p[0] = '\0';

	syslog(LOG_INFO, "Started:%s", buf);
}
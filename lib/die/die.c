#include <sys/types.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <fsyscall/private.h>
#include <fsyscall/private/die.h>

static die_log log = syslog;

void
output(const char *msg)
{
	fprintf(stderr, "%s[%d]: %s\n", getprogname(), getpid(), msg);
	log(LOG_ERR, "%s", msg);
}

void
die_with_message(int eval, const char *dying_message)
{
	output(dying_message);
	output("died.");
	exit(eval);
	/* NOTREACHED */
}

static void
vdiec(int eval, int code, const char *fmt, va_list ap)
{
	char buf[4096], msg[4096];

	vsnprintf(buf, array_sizeof(buf), fmt, ap);
	snprintf(msg, array_sizeof(msg), "%s: %s", buf, strerror(code));
	die_with_message(eval, msg);
	/* NOTREACHED */
}

void
diex(int eval, const char *fmt, ...)
{
	va_list ap;
	char buf[4096];

	va_start(ap, fmt);
	vsnprintf(buf, array_sizeof(buf), fmt, ap);
	va_end(ap);
	die_with_message(eval, buf);
}

void
diec(int eval, int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vdiec(eval, code, fmt, ap);
	va_end(ap);
}

void
die(int eval, const char *fmt, ...)
{
	va_list ap;
	int errnum;

	errnum = errno;

	va_start(ap, fmt);
	vdiec(eval, errnum, fmt, ap);
	va_end(ap);
}

static char asserting_message[1024];

void
__build_asserting_message(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(asserting_message, sizeof(asserting_message), fmt, ap);
	va_end(ap);
}

void
__die_for_assertion(const char *filename, int lineno, const char *expr)
{
	size_t msgsize;
	const char *fmt = "assertion at %s:%u for %s: %s";
	char msg[8192];

	msgsize = sizeof(msg);
	snprintf(msg, msgsize, fmt, filename, lineno, expr, asserting_message);
	die_with_message(128, msg);
}

die_log
libdie_init(die_log f)
{
	die_log old;

	old = log;
	log = f;

	return (old);
}

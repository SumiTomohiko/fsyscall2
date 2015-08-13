#include <sys/param.h>
#include <sys/proc.h>
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/sysproto.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static const char *
get_how_string(int how)
{

#define	RETURN(x)	case x: return (#x)
	switch (how) {
	RETURN(SIG_BLOCK);
	RETURN(SIG_UNBLOCK);
	RETURN(SIG_SETMASK);
#undef	RETURN
	default:
		return ("invalid");
	}
}

struct signal_definition {
	int value;
	const char *name;
};

#define	DEFINE_SIGNAL(sig)	{ sig, #sig }

static struct signal_definition signal_definitions[] = {
	DEFINE_SIGNAL(SIGHUP), DEFINE_SIGNAL(SIGINT), DEFINE_SIGNAL(SIGQUIT),
	DEFINE_SIGNAL(SIGILL), DEFINE_SIGNAL(SIGTRAP), DEFINE_SIGNAL(SIGABRT),
	DEFINE_SIGNAL(SIGEMT), DEFINE_SIGNAL(SIGFPE), DEFINE_SIGNAL(SIGKILL),
	DEFINE_SIGNAL(SIGBUS), DEFINE_SIGNAL(SIGSEGV), DEFINE_SIGNAL(SIGSYS),
	DEFINE_SIGNAL(SIGPIPE), DEFINE_SIGNAL(SIGALRM), DEFINE_SIGNAL(SIGTERM),
	DEFINE_SIGNAL(SIGURG), DEFINE_SIGNAL(SIGSTOP), DEFINE_SIGNAL(SIGTSTP),
	DEFINE_SIGNAL(SIGCONT), DEFINE_SIGNAL(SIGCHLD), DEFINE_SIGNAL(SIGTTIN),
	DEFINE_SIGNAL(SIGTTOU), DEFINE_SIGNAL(SIGIO), DEFINE_SIGNAL(SIGXCPU),
	DEFINE_SIGNAL(SIGXFSZ), DEFINE_SIGNAL(SIGVTALRM),
	DEFINE_SIGNAL(SIGPROF), DEFINE_SIGNAL(SIGWINCH), DEFINE_SIGNAL(SIGINFO),
	DEFINE_SIGNAL(SIGUSR1), DEFINE_SIGNAL(SIGUSR2), DEFINE_SIGNAL(SIGTHR)
};

static const int nsignal_definitions = array_sizeof(signal_definitions);

static int
get_sigset_string(char *buf, size_t bufsize, sigset_t *set)
{
	struct signal_definition *def;
	size_t len, size;
	int i;
	char *sep;

	len = 0;
	sep = "";
	for (i = 0; i < nsignal_definitions; i++) {
		def = &signal_definitions[i];
		if (!SIGISMEMBER(*set, def->value)) {
			continue;
		}
		size = bufsize - len;
		len += snprintf(&buf[len], size, "%s%s", sep, def->name);
		sep = ",";
	}
	if (len == 0)
		snprintf(buf, bufsize, "nothing");

	return (0);
}

static int
execute_call(struct thread *td, int how, sigset_t *set)
{
	struct payload *payload;
	int error;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);
	error = fsyscall_payload_add_int(payload, how);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_sigset(payload, set);
	if (error != 0)
		goto exit;

	error = fmaster_write_payloaded_command(td, SIGPROCMASK_CALL, payload);
	if (error != 0)
		goto  exit;

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
fmaster_sigprocmask_main(struct thread *td, int how, sigset_t *set,
			 struct fmaster_sigprocmask_args *uap)
{
	int error;

	error = execute_call(td, how, set);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_generic32(td, SIGPROCMASK_RETURN);
	if ((error != 0) || (td->td_retval[0] != 0))
		return (error);
	error = sys_sigprocmask(td, (struct sigprocmask_args *)uap);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_sigprocmask(struct thread *td, struct fmaster_sigprocmask_args *uap)
{
	struct timeval time_start;
	const sigset_t *set;
	sigset_t kset, *oset;
	int error, how;
	const char *name = "sigprocmask";
	char buf[256];

	how = uap->how;
	set = uap->set;
	oset = uap->oset;
	if (set != NULL) {
		error = copyin(set, &kset, sizeof(kset));
		if (error != 0)
			return (error);
		error = get_sigset_string(buf, sizeof(buf), &kset);
		if (error != 0)
			return (error);
	}
	else
		snprintf(buf, sizeof(buf), "null");

	fmaster_log(td, LOG_DEBUG,
		    "%s: started: how=%d (%s), set=%p (%s), oset=%p",
		    name, how, get_how_string(how), set, buf, oset);
	microtime(&time_start);

	error = fmaster_sigprocmask_main(td, how, &kset, uap);

	fmaster_log_syscall_end(td, name, &time_start, error);

	return (error);
}

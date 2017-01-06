#include <sys/param.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <err.h>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <fsyscall/private.h>
#include <fsyscall/private/close_or_die.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/fork_or_die.h>
#include <fsyscall/run_master.h>

static void
info(const char *fmt, ...)
{
	va_list ap;
	char buf[8192];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	fprintf(stderr, "%s\n", buf);
}

static void
start_slave(in_port_t port, bool ssl, const char *keystore,
	    const char *password)
{
	char *argv[10], dir[MAXPATHLEN], keystorebuf[1024], passwordbuf[1024];
	char portbuf[32], sslbuf[256];

	snprintf(sslbuf, sizeof(sslbuf),
		 "-Dfsyscall.ssl=%s", ssl ? "true" : "false");
	snprintf(keystorebuf, sizeof(keystorebuf),
		 "-Dfsyscall.keystore=%s", keystore);
	snprintf(passwordbuf, sizeof(passwordbuf),
		 "-Dfsyscall.keystore_password=%s", password);
	snprintf(portbuf, sizeof(portbuf), "%d", port);
	if (getwd(dir) == NULL)
		die(1, "getwd(2) failed");
	argv[0] = "java";
	argv[1] = "-classpath";
	argv[2] = "java/build/libs/fsyscall-slave.jar";
	argv[3] = sslbuf;
	argv[4] = keystorebuf;
	argv[5] = passwordbuf;
	argv[6] = "jp.gr.java_conf.neko_daisuki.fsyscall.slave.Application";
	argv[7] = portbuf;
	argv[8] = dir;
	argv[9] = NULL;
	execvp(argv[0], argv);
	/* NOTREACHED */
	die(1, "failed to execvp");
}

static int
bind_port(in_port_t port)
{
	struct sockaddr_in addr;
	int optval, sock;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1)
		die(1, "cannot socket(2)");
	optval = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval,
		       sizeof(optval)) == -1)
		die(1, "cannot setsockopt(2)");
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) == -1)
		die(1, "cannot bind(2)");
	if (listen(sock, 0) == -1)
		die(1, "cannot listen(2)");

	return (sock);
}

static void
wait_connect(int sock)
{
	struct kevent changelist[1], eventlist[1];
	struct timespec timeout;
	int kq, nkev;

	kq = kqueue();
	if (kq == -1)
		die(1, "cannot kqueue(2)");

	EV_SET(&changelist[0], sock, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0,
	       NULL);
	timeout.tv_sec = 4;
	timeout.tv_nsec = 0;
	nkev = kevent(kq, changelist, array_sizeof(changelist), eventlist,
		      array_sizeof(eventlist), &timeout);
	switch (nkev) {
	case -1:
		die(1, "cannot kevent(2)");
	case 0:
		diex(1, "timeout for connection");
	default:
		break;
	}

	close_or_die(kq);
}

static void
do_kill(pid_t pid)
{

	if (kill(pid, SIGKILL) == -1)
		warn("cannot SIGKILL to %d", pid);
}

static void
wait_child_term(pid_t master_pid, pid_t slave_pid)
{
	struct kevent changelist[2], eventlist[2];
	struct timespec timeout;
	size_t npids;
	pid_t pid, pids[2];
	int kq, i, incomplete, nkev, status[2];
	const char *which;

	npids = array_sizeof(pids);
	pids[0] = master_pid;
	pids[1] = slave_pid;

	kq = kqueue();
	if (kq == -1)
		die(1, "cannot kqueue(2)");
	for (i = 0; i < npids; i++)
		EV_SET(&changelist[i], pids[i], EVFILT_PROC, EV_ADD | EV_ENABLE,
		       NOTE_EXIT, (intptr_t)&status[i], NULL);
	timeout.tv_sec = 120;
	timeout.tv_nsec = 0;
	nkev = kevent(kq, changelist, array_sizeof(changelist), eventlist,
		      array_sizeof(eventlist), &timeout);
	switch (nkev) {
	case -1:
		die(1, "kevent(2)");
		/* NOTREACHED */
	case 0:
		info("both of the master and the slave timeouted");
		for (i = 0; i < npids; i++)
			do_kill(pids[i]);
		break;
	case 1:
		incomplete = eventlist[0].ident == changelist[0].ident ? 1 : 0;
		nkev = kevent(kq, &changelist[incomplete], 1, eventlist, 1,
			      &timeout);
		switch (nkev) {
		case -1:
			die(1, "kevent(2)");
			/* NOTREACHED */
		case 0:
			which = changelist[incomplete].ident == master_pid
				? "master"
				: "slave";
			info("the %s timeouted", which);
			do_kill(pids[incomplete]);
			break;
		case 1:
			return;
		default:
			diex(1, "kevent(2) returned invalid value: %d", nkev);
			/* NOTREACHED */
		}
		break;
	case 2:
		return;
	default:
		diex(1, "kevent(2) returned invalid value: %d", nkev);
		/* NOTREACHED */
	}
}

static void
waitpid_or_die(pid_t pid, int *status)
{

	if (waitpid(pid, status, 0) == -1)
		die(1, "cannot waitpid(2)");
}

static void
report_abnormal_termination(const char *name, int status)
{
	int sig;
	const char *fmt, *prog;

	if (WIFEXITED(status))
		return;
	prog = getprogname();
	info("%s: %s terminated abnormally", prog, name);
	if (WIFSIGNALED(status)) {
		sig = WTERMSIG(status);
		info("%s:   signaled (%d, SIG%s)", prog, sig, sys_signame[sig]);
	}
}

int
main(int argc, char *argv[])
{
	static struct option opts[] = {
		{ "ssl", no_argument, NULL, 's' },
		{ "cert", required_argument, NULL, 'c' },
		{ "private", required_argument, NULL, 'v' },
		{ "keystore", required_argument, NULL, 'k' },
		{ "keystore-password", required_argument, NULL, 'p' },
		{ NULL, 0, NULL, 0 }
	};

	SSL *ssl;
	SSL_CTX *ctx;
	pid_t master_pid, slave_pid;
	int d, master_status, ret, slave_status, sock;
	const in_port_t port = 54345;
	bool over_ssl;
	char cert[MAXPATHLEN], ch, keystore[MAXPATHLEN], password[32];
	char private[MAXPATHLEN];

	over_ssl = false;
	cert[0] = '\0';
	private[0] = '\0';
	keystore[0] = '\0';
	password[0] = '\0';

	while ((ch = getopt_long(argc, argv, "", opts, NULL)) != -1)
		switch (ch) {
		case 'c':
			strncpy(cert, optarg, sizeof(cert));
			break;
		case 'k':
			strncpy(keystore, optarg, sizeof(keystore));
			break;
		case 'p':
			strncpy(password, optarg, sizeof(password));
			break;
		case 's':
			over_ssl = true;
			break;
		case 'v':
			strncpy(private, optarg, sizeof(private));
			break;
		case ':':
			diex(1, "no parameters given");
			/* NOTREACHED */
		case '?':
			diex(1, "unknown argument given");
			/* NOTREACHED */
		default:
			diex(1, "unexpected getopt_long(3) behavior");
			/* NOTREACHED */
		}
	if (over_ssl) {
		if (strlen(private) == 0)
			diex(1, "no private key given for SSL");
		if (strlen(cert) == 0)
			diex(1, "no certificate given for SSL");
		if (strlen(keystore) == 0)
			diex(1, "no keystore given for SSL");
		if (strlen(password) == 0)
			diex(1, "no keystore password given for SSL");
	}

	openlog(getprogname(), LOG_PID, LOG_LOCAL0);

	sock = bind_port(port);

	slave_pid = fork_or_die();
	if (slave_pid == 0) {
		close_or_die(sock);
		start_slave(port, over_ssl, keystore, password);
		/* NOTREACHED */
		return (32);
	}

	wait_connect(sock);
	d = accept(sock, NULL, 0);
	if (d == -1)
		die(1, "cannot accept(2)");
	close_or_die(sock);

	master_pid = fork_or_die();
	if (master_pid == 0) {
		extern char *const *environ;
		if (!over_ssl)
			ret = fsyscall_run_master_nossl(d, d, argc - optind,
							&argv[optind], environ);
		else {
			SSL_library_init();
			SSL_load_error_strings();
			ctx = SSL_CTX_new(SSLv23_server_method());
			if (ctx == NULL)
				diex(1, "cannot SSL_CTX_new(3)");
			ret = SSL_CTX_use_certificate_file(ctx, cert,
							   SSL_FILETYPE_PEM);
			if (ret != 1) {
				ERR_print_errors_fp(stderr);
				diex(1,
				     "cannot SSL_CTX_use_certificate_file(3)");
			}
			ret = SSL_CTX_use_PrivateKey_file(ctx, private,
							  SSL_FILETYPE_PEM);
			if (ret != 1) {
				ERR_print_errors_fp(stderr);
				diex(1,
				     "cannot SSL_CTX_use_PrivateKey_file(3)");
			}
			if (!SSL_CTX_check_private_key(ctx))
				diex(1, "wrong keys");
			ssl = SSL_new(ctx);
			if (ssl == NULL)
				diex(1, "cannot SSL_new(3)");
			if (SSL_set_fd(ssl, d) != 1)
				diex(1, "cannot SSL_set_fd(3)");
			if (SSL_accept(ssl) != 1)
				diex(1, "cannot SSL_accept(3)");

			ret = fsyscall_run_master_ssl(ssl, argc - optind,
						      &argv[optind], environ);

			SSL_free(ssl);
			SSL_CTX_free(ctx);
		}
		return (ret);
	}

	close_or_die(d);
	wait_child_term(master_pid, slave_pid);
	waitpid_or_die(slave_pid, &slave_status);
	waitpid_or_die(master_pid, &master_status);
	report_abnormal_termination("slave", slave_status);
	report_abnormal_termination("master", master_status);
	if (!WIFEXITED(slave_status) || !WIFEXITED(master_status))
		return (250);

	return (WEXITSTATUS(slave_status));
}

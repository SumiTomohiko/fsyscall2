#include <sys/param.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <fsyscall/private.h>
#include <fsyscall/private/close_or_die.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/fork_or_die.h>
#include <fsyscall/start_master.h>

static void
start_slave(in_port_t port)
{
	char *argv[7], dir[MAXPATHLEN], portbuf[32];

	snprintf(portbuf, sizeof(portbuf), "%d", port);
	if (getwd(dir) == NULL)
		die(1, "getwd(2) failed");
	argv[0] = "java";
	argv[1] = "-classpath";
	argv[2] = "java/build/libs/fsyscall-slave.jar";
	argv[3] = "jp.gr.java_conf.neko_daisuki.fsyscall.slave.Application";
	argv[4] = portbuf;
	argv[5] = dir;
	argv[6] = NULL;
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
wait_child_term(pid_t pids[2])
{
	struct kevent changelist[2], eventlist[2];
	struct timespec timeout;
	size_t npids;
	pid_t pid;
	int kq, i, incomplete, nkev, status[2];

	npids = 2;

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
	fprintf(stderr, "%s: %s terminated abnormally\n", prog, name);
	if (WIFSIGNALED(status)) {
		fmt = "%s:   signaled (%d, SIG%s)\n";
		sig = WTERMSIG(status);
		fprintf(stderr, fmt, prog, sig, sys_signame[sig]);
	}
}

int
main(int argc, char *argv[])
{
	pid_t master_pid, pids[2], slave_pid;
	int d, master_status, slave_status, sock;
	const in_port_t port = 54345;

	sock = bind_port(port);

	slave_pid = fork_or_die();
	if (slave_pid == 0) {
		close_or_die(sock);
		start_slave(port);
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
		extern char **environ;
		fsyscall_start_master(d, d, argc - 1, &argv[1], environ);
		/* NOTREACHED */
		return (64);
	}

	close_or_die(d);
	pids[0] = slave_pid;
	pids[1] = master_pid;
	wait_child_term(pids);
	waitpid_or_die(slave_pid, &slave_status);
	waitpid_or_die(master_pid, &master_status);
	report_abnormal_termination("slave", slave_status);
	report_abnormal_termination("master", master_status);
	if (!WIFEXITED(slave_status) || !WIFEXITED(master_status))
		return (250);

	return (WEXITSTATUS(slave_status));
}

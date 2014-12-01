#include <tiny_runtime.h>

static struct sockaddr_storage addr, client_addr;

#define	SIGNAL	SIGUSR1

static void
signal_handler(int sig)
{
}

static int
client_main(struct sockaddr *name, tr_connect_callback callback)
{
	sigset_t oset, set;
	int error, retval, sig, sock;

	if (sigemptyset(&set) == -1)
		return (128);
	if (sigaddset(&set, SIGNAL) == -1)
		return (129);
	if (sigwait(&set, &sig) != 0)
		return (130);
	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (131);

	error = connect(sock, name, name->sa_len);
	if (error == -1)
		return (132);
	retval = callback(sock);

	error = close(sock);
	if (error == -1)
		return (133);

	return (retval);
}

static int
server_main(pid_t pid, struct sockaddr *addr, tr_accept_callback callback)
{
	struct sockaddr *pclient_addr;
	socklen_t addrlen;
	int error, fd, retval, sock, status;

	sock = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sock == -1)
		return (192);
	if (bind(sock, addr, addr->sa_len) == -1)
		return (193);
	if (listen(sock, 0) == -1)
		return (194);
	if (kill(pid, SIGNAL) == -1)
		return (195);

	addrlen = sizeof(client_addr);
	pclient_addr = (struct sockaddr *)&client_addr;
	fd = accept(sock, pclient_addr, &addrlen);
	if (fd == -1)
		return (196);

	retval = callback(fd, pclient_addr, addrlen);

	error = wait4(pid, &status, 0, NULL);
	if (error == -1)
		return (197);
	if (!WIFEXITED(status))
		return (198);
	if (WEXITSTATUS(status) != 0)
		return (199);

	if (close(fd) != 0)
		return (200);
	if (close(sock) != 0)
		return (201);

	return (retval);
}

static int
run_client_server(const char *path, tr_accept_callback accept_callback,
		  tr_connect_callback connect_callback)
{
	struct sigaction act;
	struct sockaddr *paddr;
	struct sockaddr_un *punaddr;
	sigset_t set;
	pid_t pid;
	int error, retval, status;

	act.sa_handler = signal_handler;
	act.sa_flags = 0;
	if (sigemptyset(&act.sa_mask) == -1)
		return (225);
	if (sigaction(SIGNAL, &act, NULL) == -1)
		return (226);
	if (sigemptyset(&set) == -1)
		return (227);
	if (sigaddset(&set, SIGNAL) == -1)
		return (228);
	if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
		return (229);

	punaddr = (struct sockaddr_un *)&addr;
	punaddr->sun_family = AF_LOCAL;
	strcpy(punaddr->sun_path, path);
	punaddr->sun_len = SUN_LEN(punaddr);

	paddr = (struct sockaddr *)&addr;
	pid = fork();
	switch (pid) {
	case -1:
		return (230);
	case 0:
		return (client_main(paddr, connect_callback));
	default:
		break;
	}

	retval = server_main(pid, paddr, accept_callback);

	return (retval);
}

static int
nop_accept_callback(int s, struct sockaddr *addr, socklen_t addrlen)
{

	return (0);
}

static int
nop_connect_callback(int s)
{

	return (0);
}

int
tr_run_client_server(const char *path, tr_accept_callback ac,
		     tr_connect_callback cc)
{
	tr_accept_callback acb;
	tr_connect_callback ccb;
	int error;

	acb = ac != NULL ? ac : nop_accept_callback;
	ccb = cc != NULL ? cc : nop_connect_callback;

	error = run_client_server(path, acb, ccb);

	return (error);
}

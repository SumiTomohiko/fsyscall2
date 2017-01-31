#include <sys/types.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <fsyscall.h>
#include <fsyscall/private.h>
#include <fsyscall/private/atoi_or_die.h>
#include <fsyscall/private/close_or_die.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmhub.h>
#include <fsyscall/private/fork_or_die.h>
#include <fsyscall/private/geterrorname.h>
#include <fsyscall/private/hub.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/io_or_die.h>
#include <fsyscall/private/list.h>
#include <fsyscall/private/log.h>
#include <fsyscall/private/malloc_or_die.h>
#include <fsyscall/private/payload.h>
#include <fsyscall/private/pipe_or_die.h>

#define	INVALID_FD	-1

struct master {
	struct item item;
	pair_id_t pair_id;
	pid_t pid;		/* used to signal */
	struct io io;
	bool exited;
};

struct mhub {
	struct connection shub;
	struct list masters;
	int fork_sock;
	pair_id_t next_pair_id;
	struct list fork_info;
	struct io **ios;	/* "struct io *" array used in mainloop */
	int nmasters;
};

#define	TOKEN_SIZE	64

struct fork_info {
	struct item item;
	pair_id_t parent_pair_id;
	pair_id_t child_pair_id;
	char token[TOKEN_SIZE];
};

static void
log2(int priority, const char *msg)
{

	syslog(priority, "fmhub: %s", msg);
}

static void
vlog(int priority, const char *fmt, va_list ap)
{
	char buf[8192];

	vsnprintf(buf, sizeof(buf), fmt, ap);
	log2(priority, buf);
}

static void
log(int priority, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(priority, fmt, ap);
	va_end(ap);
}

static void
negotiate_version_with_master(struct master *master)
{
	uint8_t request, ver = 0;

	read_or_die(&master->io, &request, sizeof(request));
	assert(request == 0);
	write_or_die(&master->io, &ver, sizeof(ver));
	log(LOG_INFO, "protocol version for master is %d.", ver);
}

static void
negotiate_version_with_shub(struct mhub *mhub)
{
	uint8_t request;
	uint8_t ver = 0;

	read_or_die(mhub->shub.conn_io, &request, sizeof(request));
	assert(request == 0);
	write_or_die(mhub->shub.conn_io, &ver, sizeof(ver));
	log(LOG_INFO, "protocol version for shub is %d.", ver);
}

static const char *
dump_master(char *buf, size_t bufsize, const struct master *master)
{
	const char *fmt = "pair_id=%ld, pid=%d, io=%s";
	char s[256];

	io_dump(&master->io, s, sizeof(s));
	snprintf(buf, bufsize, fmt, master->pair_id, master->pid, s);

	return (buf);
}

#if 0
static void
dump_masters(struct mhub *mhub)
{
	struct master *master;
	char buf[1024];

	master = (struct master *)FIRST_ITEM(&mhub->masters);
	while (!IS_LAST(master)) {
		dump_master(buf, sizeof(buf), master);
		log(LOG_DEBUG, "master: %s", buf);
		master = (struct master *)ITEM_NEXT(master);
	}
}
#endif

static int
find_syscall()
{
	struct module_stat stat;
	int modid;
	const char *modname = "sys/fmaster";

	modid = modfind(modname);
	if (modid == -1)
		die(-1, "cannot modfind %s", modname);

	stat.version = sizeof(stat);
	if (modstat(modid, &stat) != 0)
		die(-1, "cannot modstat %s", modname);

	return (stat.data.intval);
}

static void
exec_master(int syscall_num, int rfd, int wfd, const char *fork_sock, int argc,
	    char *const argv[], char *const envp[])
{
	char **args;
	int i;

	args = (char **)alloca(sizeof(char *) * (argc + 1));
	for (i = 0; i < argc; i++) {
		args[i] = (char *)alloca(sizeof(char) * (strlen(argv[i]) + 1));
		strcpy(args[i], argv[i]);
	}
	args[i] = NULL;

	syscall(syscall_num, rfd, wfd, fork_sock, args[0], args, envp);
	die(1, "fmaster_start failed");
	/* NOTREACHED */
}

static bool
compare_pair_id_of_master(struct item *item, void *bonus)
{
	struct master *master;
	pair_id_t *pair_id;

	master = (struct master *)item;
	pair_id = (pair_id_t *)bonus;

	return (master->pair_id == *pair_id);
}

static struct master *
find_master_of_pair_id(struct mhub *mhub, pair_id_t pair_id)
{
	struct item *item;

	item = list_search(&mhub->masters, compare_pair_id_of_master, &pair_id);
	die_if_false(item != NULL, ("pair_id: %d", pair_id));

	return ((struct master *)item);
}

static void
transfer_payload_to_master(struct mhub *mhub, command_t cmd)
{
	struct master *master;
	struct io *dst, *src;
	uint32_t payload_size;
	pair_id_t pair_id;
	int payload_len;
	char payload_buf[FSYSCALL_BUFSIZE_UINT32];
	const char *fmt = "%s: pair_id=%ld, payload_size=%u";

	src = mhub->shub.conn_io;
	pair_id = read_pair_id(src);
	payload_len = read_numeric_sequence(
		src,
		payload_buf,
		array_sizeof(payload_buf));
	payload_size = decode_uint32(payload_buf, payload_len);

	log(LOG_DEBUG, fmt, get_command_name(cmd), pair_id, payload_size);

	master = find_master_of_pair_id(mhub, pair_id);
	dst = &master->io;
	write_command(dst, cmd);
	write_or_die(dst, payload_buf, payload_len);
	transfer(src, dst, payload_size);
}

static bool
compare_token(struct item *item, void *bonus)
{
	struct fork_info *fi;
	const char *token;

	fi = (struct fork_info *)item;
	token = (const char *)bonus;

	return (memcmp(fi->token, token, TOKEN_SIZE) == 0);
}

static struct fork_info *
find_fork_info_of_token(struct mhub *mhub, char *token)
{
	struct item *item;

	item = list_search(&mhub->fork_info, compare_token, token);

	return ((struct fork_info *)item);
}

static bool
compare_pair_id_of_fork_info(struct item *item, void *bonus)
{
	struct fork_info *fi;
	pair_id_t *pair_id;

	fi = (struct fork_info *)item;
	pair_id = (pair_id_t *)bonus;

	return (fi->parent_pair_id == *pair_id);
}

static struct fork_info *
find_fork_info_of_pair_id(struct mhub *mhub, pair_id_t pair_id)
{
	struct list *list;
	struct item *item;

	list = &mhub->fork_info;
	item = list_search(list, compare_pair_id_of_fork_info, &pair_id);

	return ((struct fork_info *)item);
}

static void
log_new_master(struct master *master)
{
	pair_id_t pair_id;
	const char *fmt = "new master: pair_id=%ld, pid=%d, io=%s";
	char buf[256];

	pair_id = master->pair_id;
	io_dump(&master->io, buf, sizeof(buf));
	log(LOG_DEBUG, fmt, pair_id, master->pid, buf);
}

static void
alloc_ios(struct mhub *mhub)
{
	size_t size;

	free(mhub->ios);

	size = sizeof(struct io *) * (mhub->nmasters + 1);
	mhub->ios = (struct io **)malloc_or_die(size);
}

static struct master *
create_master(struct mhub *mhub, pair_id_t pair_id, pid_t pid, int rfd, int wfd)
{
	struct master *master;

	master = (struct master *)malloc_or_die(sizeof(*master));
	master->pair_id = pair_id;
	master->pid = pid;
	io_init_nossl(&master->io, rfd, wfd, vlog);
	master->exited = false;

	mhub->nmasters++;
	alloc_ios(mhub);

	log_new_master(master);

	return (master);
}

static void
process_signaled(struct mhub *mhub, command_t cmd)
{
	struct io *io;
	pair_id_t pair_id;
	pid_t pid;
	int sig;
	const char *errfmt = "kill(2) failed: pair_id=%ld, pid=%d, sig=%d (SIG%"
			     "s): %s";
	const char *fmt = "signaled: pair_id=%ld, pid=%d, signal=%d (SIG%s)";
	const char *cause, *signame;
	char c;

	io = mhub->shub.conn_io;
	pair_id = read_pair_id(io);
	read_or_die(io, &c, sizeof(c));
	sig = (int)c;

	pid = find_master_of_pair_id(mhub, pair_id)->pid;
	signame = sys_signame[sig];
	log(LOG_DEBUG, fmt, pair_id, pid, sig, signame);
	if (kill(pid, sig) != 0) {
		cause = strerror(errno);
		log(LOG_ERR, errfmt, pair_id, pid, sig, signame, cause);
	}
}

static void
wait_fork_child(struct mhub *mhub)
{
	struct timeval timeout;
	fd_set fds;
	int fd, n;

	fd = mhub->fork_sock;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	timeout.tv_sec = 60;
	timeout.tv_usec = 0;

	n = select(fd + 1, &fds, NULL, NULL, &timeout);
	switch (n) {
	case -1:
		die(-1, "select failed");
		/* NOTREACHED */
	case 0:
		die(1, "select(2) for fork child timed out");
		/* NOTREACHED */
	default:
		break;
	}
}

static void
process_fork_socket(struct mhub *mhub)
{
	struct master *master;
	struct sockaddr_storage addr;
	struct fork_info *fi;
	struct io io;
	payload_size_t len;
	socklen_t addrlen;
	pid_t pid;
	int sock;
	const char *fmt = "A new master (pair id: %ld) has come.";
	char token[TOKEN_SIZE];

	addrlen = sizeof(addr);
	sock = accept(mhub->fork_sock, (struct sockaddr *)&addr, &addrlen);
	if (sock == -1)
		die(1, "accept(2) failed");
	io_init_nossl(&io, sock, sock, vlog);
	read_or_die(&io, token, sizeof(token));
	fi = find_fork_info_of_token(mhub, token);
	if (fi == NULL)
		die(1, "Cannot find token %s", token);
	assert(fi != NULL);
	log(LOG_INFO, fmt, fi->child_pair_id);

	pid = read_pid(&io, &len);
	master = create_master(mhub, fi->child_pair_id, pid, sock, sock);
	PREPEND_ITEM(&mhub->masters, master);

	REMOVE_ITEM(fi);
	free(fi);
}

static void
transfer_token(struct mhub *mhub, command_t cmd)
{
	struct fork_info *fi;
	struct payload *payload;
	struct io *dst, *src;
	payload_size_t buf_size, payload_size;
	pair_id_t pair_id;
	char *buf;

	src = mhub->shub.conn_io;
	pair_id = read_pair_id(src);
	buf_size = read_payload_size(src);
	buf = (char *)alloca(buf_size);
	read_or_die(src, buf, buf_size);

	fi = find_fork_info_of_pair_id(mhub, pair_id);
	assert(fi != NULL);

	payload = payload_create();
	payload_add_uint64(payload, TOKEN_SIZE);
	payload_add(payload, fi->token, TOKEN_SIZE);
	payload_size = payload_get_size(payload);

	dst = &find_master_of_pair_id(mhub, pair_id)->io;
	write_command(dst, cmd);
	write_payload_size(dst, payload_size + buf_size);
	write_or_die(dst, payload_get(payload), payload_size);
	write_or_die(dst, buf, buf_size);

	payload_dispose(payload);

	wait_fork_child(mhub);
	process_fork_socket(mhub);
}

static int
process_shub(struct mhub *mhub, struct io *io)
{
	command_t cmd;
	const char *fmt = "processing %s from the slave hub.";

	if (io_read_command(io, &cmd) == -1)
		return (-1);
	log(LOG_DEBUG, fmt, get_command_name(cmd));
	switch (cmd) {
	case SIGNALED:
		process_signaled(mhub, cmd);
		break;
	case FORK_RETURN:
	case THR_NEW_RETURN:
		transfer_token(mhub, cmd);
		break;
	case CLOSE_RETURN:
	case POLL_RETURN:
	case SELECT_RETURN:
	case CONNECT_RETURN:
	case BIND_RETURN:
	case GETPEERNAME_RETURN:
	case GETSOCKNAME_RETURN:
	case ACCEPT_RETURN:
	case GETSOCKOPT_RETURN:
	case SETSOCKOPT_RETURN:
	case KEVENT_RETURN:
	case POLL_ENDED:
	case SIGPROCMASK_RETURN:
	case SENDMSG_RETURN:
	case RECVMSG_RETURN:
	case UTIMES_RETURN:
	case GETDIRENTRIES_RETURN:
	case FCNTL_RETURN:
	case OPENAT_RETURN:
	case ACCEPT4_RETURN:
#include "dispatch_ret.inc"
		transfer_payload_to_master(mhub, cmd);
		break;
	default:
		diex(-1, "unknown command (%d) from the slave hub.", cmd);
	}

	return (0);
}

static void
dispose_master(struct mhub *mhub, struct master *master)
{
	char buf[1024];

	dump_master(buf, sizeof(buf), master);
	log(LOG_DEBUG, "dispose master: %s", buf);

	mhub->nmasters--;
	alloc_ios(mhub);

	REMOVE_ITEM(master);
	hub_close_fds_or_die(&master->io);
	free(master);
}

static int
process_exit(struct mhub *mhub, struct master *master)
{
	struct io *io;
	pair_id_t pair_id;
	payload_size_t _;
	int status;

	status = read_int32(&master->io, &_);
	pair_id = master->pair_id;
	log(LOG_DEBUG, "EXIT_CALL: pair_id=%ld, status=%d", pair_id, status);

	io = mhub->shub.conn_io;
	write_command(io, EXIT_CALL);
	write_pair_id(io, pair_id);
	write_int32(io, status);

	master->exited = true;

	return (0);
}

static int
transfer_simple_command_from_master(struct mhub *mhub, struct master *master,
				    command_t cmd)
{
	struct io *io;
	pair_id_t pair_id;

	pair_id = master->pair_id;
	log(LOG_DEBUG, "%s: pair_id=%ld", get_command_name(cmd), pair_id);

	io = mhub->shub.conn_io;
	write_command(io, cmd);
	write_pair_id(io, pair_id);

	return (0);
}

static int
transfer_payload_from_master(struct mhub *mhub, struct master *master,
			     command_t cmd)
{
	struct io *dst, *src;
	pair_id_t pair_id;
	int len, payload_size;
	char buf[FSYSCALL_BUFSIZE_INT32];
	const char *fmt = "%s: pair_id=%ld, payload_size=%d";

	src = &master->io;
	len = io_read_numeric_sequence(src, buf, array_sizeof(buf));
	if (len == -1)
		return (-1);
	payload_size = decode_int32(buf, len);

	pair_id = master->pair_id;
	log(LOG_DEBUG, fmt, get_command_name(cmd), pair_id, payload_size);

	dst = mhub->shub.conn_io;
	write_command(dst, cmd);
	write_pair_id(dst, pair_id);
	write_or_die(dst, buf, len);
	if (io_transfer(src, dst, payload_size) == -1)
		return (-1);

	return (0);
}

static int
read_fork_kind_call(struct mhub *mhub, struct master *master, command_t cmd)
{
	int len, payload_size;
	char buf[FSYSCALL_BUFSIZE_PAYLOAD_SIZE];
	const char *fmt = "%s: pair_id=%ld, payload_size=%d", *name;

	len = io_read_numeric_sequence(&master->io, buf, array_sizeof(buf));
	if (len == -1)
		return (-1);
	payload_size = decode_int32(buf, len);
	assert(payload_size == 0);

	name = get_command_name(cmd);
	log(LOG_DEBUG, fmt, name, master->pair_id, payload_size);

	return (0);
}

static void
write_fork_kind_call(struct mhub *mhub, struct master *master, command_t cmd,
		     struct fork_info *fi)
{
	struct io *io;
	payload_size_t payload_size;
	char buf[FSYSCALL_BUFSIZE_PAIR_ID];

	payload_size = encode_pair_id(fi->child_pair_id, buf, sizeof(buf));

	io = mhub->shub.conn_io;
	write_command(io, cmd);
	write_pair_id(io, master->pair_id);
	write_payload_size(io, payload_size);
	write_or_die(io, buf, payload_size);
}

static int
process_fork_kind_call(struct mhub *mhub, struct master *master, command_t cmd)
{
	struct fork_info *fi;

	if (read_fork_kind_call(mhub, master, cmd) == -1)
		return (-1);

	fi = (struct fork_info *)malloc_or_die(sizeof(*fi));
	fi->parent_pair_id = master->pair_id;
	fi->child_pair_id = mhub->next_pair_id;
	hub_generate_token(fi->token, TOKEN_SIZE);
#if 0
	log(LOG_DEBUG, "token generated: %s", fi->token);
#endif
	mhub->next_pair_id++;
	PREPEND_ITEM(&mhub->fork_info, fi);

	write_fork_kind_call(mhub, master, cmd, fi);

	return (0);
}

static int
process_master(struct mhub *mhub, struct master *master)
{
	struct io *io;
	command_t cmd;
	pair_id_t pair_id;
	int e;
	const char *fmt = "unknown command (%d) from master (%ld)", *name;
	char buf[1024];

	io = &master->io;
	if (io_read_command(io, &cmd) == -1) {
		if (!master->exited) {
			dump_master(buf, sizeof(buf), master);
			e = io->io_error;
			log(LOG_DEBUG,
			    "read error: errno=%d (%s): %s",
			    e, geterrorname(e), buf);
		}
		return (-1);
	}
	name = get_command_name(cmd);
	pair_id = master->pair_id;
	log(LOG_DEBUG, "processing %s from the master %ld.", name, pair_id);
	switch (cmd) {
	case EXIT_CALL:
		return (process_exit(mhub, master));
	case FORK_CALL:
	case THR_NEW_CALL:
		return (process_fork_kind_call(mhub, master, cmd));
	case CLOSE_CALL:
	case POLL_CALL:
	case SELECT_CALL:
	case CONNECT_CALL:
	case BIND_CALL:
	case GETPEERNAME_CALL:
	case GETSOCKNAME_CALL:
	case ACCEPT_CALL:
	case GETSOCKOPT_CALL:
	case SETSOCKOPT_CALL:
	case KEVENT_CALL:
	case POLL_START:
	case SIGPROCMASK_CALL:
	case SENDMSG_CALL:
	case RECVMSG_CALL:
	case UTIMES_CALL:
	case GETDIRENTRIES_CALL:
	case FCNTL_CALL:
	case OPENAT_CALL:
	case ACCEPT4_CALL:
#include "dispatch_call.inc"
		return (transfer_payload_from_master(mhub, master, cmd));
	case POLL_END:
	case THR_EXIT_CALL:
		return (transfer_simple_command_from_master(mhub, master, cmd));
	default:
		diex(-1, fmt, cmd, master->pair_id);
	}

	/* NOTREACHED */
	return (-1);
}

static bool
compare_io(struct item *item, void *bonus)
{
	struct master *master;

	master = (struct master *)item;

	return (&master->io == bonus);
}

static struct master *
find_master_of_io(struct mhub *mhub, struct io *io)
{
	struct item *item;

	item = list_search(&mhub->masters, compare_io, io);
	assert(item != NULL);

	return ((struct master *)item);
}

static void
dispose_session(struct mhub *mhub)
{
	struct master *master, *next;
	int e;

	master = (struct master *)FIRST_ITEM(&mhub->masters);
	while (!IS_LAST(master)) {
		if (kill(master->pid, SIGKILL) == -1) {
			e = errno;
			log(LOG_WARNING,
			    "cannot kill master: pid=%d, errno=%d (%s)",
			    master->pid, e, geterrorname(e));
		}
		next = (struct master *)ITEM_NEXT(master);
		dispose_master(mhub, master);
		master = next;
	}
}

static int
process_fd(struct mhub *mhub, struct io *io)
{
	struct master *master;
	int e;

	if (!io_is_readable(io))
		return (0);
	if (io == mhub->shub.conn_io) {
		if (process_shub(mhub, io) == -1) {
			e = io->io_error;
			log(LOG_ERR,
			    "slave disconnected: errno=%d (%s)",
			    e, geterrorname(e));
			dispose_session(mhub);
			return (-1);
		}
		return (0);
	}

	master = find_master_of_io(mhub, io);
	if (process_master(mhub, master) == -1)
		dispose_master(mhub, master);

	return (0);
}

static int
process_fds(struct mhub *mhub)
{
	struct master *master;
	struct io **ios;
	struct timeval timeout;
	int error, i, n, nios;

	ios = mhub->ios;
	ios[0] = mhub->shub.conn_io;

	master = (struct master *)FIRST_ITEM(&mhub->masters);
	i = 1;
	while (!IS_LAST(master)) {
		ios[i] = &master->io;
		master = (struct master *)ITEM_NEXT(master);
		i++;
	}
	timeout.tv_sec = 90;
	timeout.tv_usec = 0;
	nios = mhub->nmasters + 1;
	n = io_select(nios, ios, &timeout, &error);
	switch (n) {
	case -1:
		diec(-1, error, "select failed");
		/* NOTREACHED */
	case 0:
		log(LOG_ERR, "slave timeouted");
		dispose_session(mhub);
		return (-1);
	default:
		break;
	}

	for (i = 0; i < nios; i++)
		if (process_fd(mhub, ios[i]) == -1)
			return (-1);

	return (0);
}

static void
mainloop(struct mhub *mhub)
{
	while (!IS_EMPTY(&mhub->masters))
		if (process_fds(mhub) == -1)
			break;
}

static int
mhub_main(struct mhub *mhub, const char *fork_sock, int argc,
	  char *const argv[], char *const envp[])
{
	struct master *master;
	int hub2master[2], master2hub[2], rfd, syscall_num, wfd;
	pid_t pid;
	const char *verbose;

	syscall_num = find_syscall();

	pipe_or_die(hub2master);
	pipe_or_die(master2hub);

	pid = fork_or_die();
	if (pid == 0) {
		close_or_die(hub2master[W]);
		close_or_die(master2hub[R]);

		rfd = hub2master[R];
		wfd = master2hub[W];
		exec_master(syscall_num, rfd, wfd, fork_sock, argc, argv, envp);
		/* NOTREACHED */
	}

	verbose = getenv(FSYSCALL_ENV_VERBOSE);
	if ((verbose != NULL) && (strcmp(verbose, "1") == 0))
		printf("pid of fmaster=%d\n", pid);

	close_or_die(hub2master[R]);
	close_or_die(master2hub[W]);

	master = create_master(mhub, 0, pid, master2hub[R], hub2master[W]);
	PREPEND_ITEM(&mhub->masters, master);

	negotiate_version_with_shub(mhub);
	negotiate_version_with_master(master);
	write_pair_id(mhub->shub.conn_io, master->pair_id);
	transport_fds(mhub->shub.conn_io, &master->io);

	mainloop(mhub);

	return (0);
}

static void
reset_signal_handlers()
{
	struct sigaction act;
	int i, nsigs;
	int sigs[] = { SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
		       SIGEMT, SIGFPE, SIGKILL, SIGBUS, SIGSEGV, SIGSYS,
		       SIGPIPE, SIGALRM, SIGTERM, SIGURG, SIGSTOP, SIGTSTP,
		       SIGCONT, SIGCHLD, SIGTTIN, SIGTTOU, SIGIO, SIGXCPU,
		       SIGXFSZ, SIGVTALRM, SIGPROF, SIGWINCH, SIGINFO, SIGUSR1,
		       SIGUSR2, SIGTHR, SIGLIBRT };

	act.sa_handler = SIG_DFL;
	act.sa_flags = 0;
	if (sigemptyset(&act.sa_mask) != 0)
		die(1, "cannot sigemptyset(3)");

	nsigs = array_sizeof(sigs);
	for (i = 0; i < nsigs; i++)
		if (sigaction(sigs[i], &act, NULL) == -1)
			die(1, "cannot sigaction(2)");
}

static int
fmhub_run(struct io *io, int argc, char *const argv[], char *const envp[],
	  const char *sock_path)
{
	struct mhub mhub, *pmhub;
	int status;

	pmhub = &mhub;
	log_start_message2(argc, argv, log2);

	reset_signal_handlers();

	pmhub->shub.conn_io = io;
	initialize_list(&pmhub->masters);
	pmhub->next_pair_id = 1;
	initialize_list(&pmhub->fork_info);

	pmhub->fork_sock = hub_open_fork_socket(sock_path);
	pmhub->ios = NULL;
	pmhub->nmasters = 0;
	status = mhub_main(pmhub, sock_path, argc, argv, envp);
	hub_close_fork_socket(pmhub->fork_sock);
	hub_unlink_socket(sock_path);
	log_graceful_exit2(status, log2);

	return (status);
}

int
fmhub_run_nossl(int rfd, int wfd, int argc, char *const argv[],
		char *const envp[], const char *sock_path)
{
	struct io io;
	int retval;

	io_init_nossl(&io, rfd, wfd, vlog);
	retval = fmhub_run(&io, argc, argv, envp, sock_path);

	return (retval);
}

int
fmhub_run_ssl(SSL *ssl, int argc, char *const argv[], char *const envp[],
	      const char *sock_path)
{
	struct io io;
	die_log die_log_old;
	int retval;

	die_log_old = libdie_init(log);
	io_init_ssl(&io, ssl, vlog);
	retval = fmhub_run(&io, argc, argv, envp, sock_path);
	libdie_init(die_log_old);

	return (retval);
}

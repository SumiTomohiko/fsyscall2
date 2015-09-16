#include <sys/types.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <fsyscall.h>
#include <fsyscall/private.h>
#include <fsyscall/private/atoi_or_die.h>
#include <fsyscall/private/close_or_die.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/die.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fork_or_die.h>
#include <fsyscall/private/hub.h>
#include <fsyscall/private/io.h>
#include <fsyscall/private/list.h>
#include <fsyscall/private/log.h>
#include <fsyscall/private/malloc_or_die.h>
#include <fsyscall/private/payload.h>
#include <fsyscall/private/pipe_or_die.h>

#define	INVALID_FD	-1

struct master {
	struct item item;
	pair_id_t pair_id;
	pid_t pid;
	int rfd;
	int wfd;
};

struct mhub {
	struct connection shub;
	struct list masters;
	int fork_sock;
	pair_id_t next_pair_id;
	struct list fork_info;
};

struct env {
	struct env *next;
	const char *pair;
};

#define	TOKEN_SIZE	64

struct fork_info {
	struct item item;
	pair_id_t parent_pair_id;
	pair_id_t child_pair_id;
	char token[TOKEN_SIZE];
};

static void
usage()
{
	puts("fmhub rfd wfd command...");
}

static void
negotiate_version_with_master(struct master *master)
{
	uint8_t request, ver = 0;

	read_or_die(master->rfd, &request, sizeof(request));
	assert(request == 0);
	write_or_die(master->wfd, &ver, sizeof(ver));
	syslog(LOG_INFO, "protocol version for master is %d.", ver);
}

static void
negotiate_version_with_shub(struct mhub *mhub)
{
	uint8_t request;
	uint8_t ver = 0;

	read_or_die(mhub->shub.rfd, &request, sizeof(request));
	assert(request == 0);
	write_or_die(mhub->shub.wfd, &ver, sizeof(ver));
	syslog(LOG_INFO, "protocol version for shub is %d.", ver);
}

#if 0
static void
dump_masters(struct mhub *mhub)
{
	struct master *master;
	int rfd, wfd;
	const char *fmt = "master (%p): pair_id=%ld, rfd=%d, wfd=%d";

	master = (struct master *)FIRST_ITEM(&mhub->masters);
	while (!IS_LAST(master)) {
		rfd = master->rfd;
		wfd = master->wfd;
		syslog(LOG_DEBUG, fmt, master, master->pair_id, rfd, wfd);
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
exec_master(int syscall_num, int rfd, int wfd, const char *fork_sock, int argc, char *argv[], const char *envp[])
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
	die(1, "fmaster_evecve failed");
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
	uint32_t payload_size;
	pair_id_t pair_id;
	int payload_len, rfd, wfd;
	char payload_buf[FSYSCALL_BUFSIZE_UINT32];
	const char *fmt = "%s: pair_id=%ld, payload_size=%u";
	const char *name;

	rfd = mhub->shub.rfd;
	pair_id = read_pair_id(rfd);
	payload_len = read_numeric_sequence(
		rfd,
		payload_buf,
		array_sizeof(payload_buf));
	payload_size = decode_uint32(payload_buf, payload_len);

	name = get_command_name(cmd);
	syslog(LOG_DEBUG, fmt, name, pair_id, payload_size);

	master = find_master_of_pair_id(mhub, pair_id);
	wfd = master->wfd;
	write_command(wfd, cmd);
	write_or_die(wfd, payload_buf, payload_len);
	transfer(rfd, wfd, payload_size);
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
	const char *fmt = "new master: pair_id=%ld, pid=%d, rfd=%d, wfd=%d";

	pair_id = master->pair_id;
	syslog(LOG_DEBUG, fmt, pair_id, master->pid, master->rfd, master->wfd);
}

static struct master *
create_master(struct mhub *mhub, pair_id_t pair_id, pid_t pid, int rfd, int wfd)
{
	struct master *master;

	master = (struct master *)malloc_or_die(sizeof(*master));
	master->pair_id = pair_id;
	master->pid = pid;
	master->rfd = rfd;
	master->wfd = wfd;
	log_new_master(master);

	return (master);
}

static void
process_signaled(struct mhub *mhub, command_t cmd)
{
	pair_id_t pair_id;
	pid_t pid;
	int rfd, sig;
	const char *errfmt = "kill(2) failed: pair_id=%ld, pid=%d, sig=%d (SIG%"
			     "s): %s";
	const char *fmt = "signaled: pair_id=%ld, pid=%d, signal=%d (SIG%s)";
	const char *cause, *signame;
	char c;

	rfd = mhub->shub.rfd;
	pair_id = read_pair_id(rfd);
	read_or_die(rfd, &c, sizeof(c));
	sig = (int)c;

	pid = find_master_of_pair_id(mhub, pair_id)->pid;
	signame = sys_signame[sig];
	syslog(LOG_DEBUG, fmt, pair_id, pid, sig, signame);
	if (kill(pid, sig) != 0) {
		cause = strerror(errno);
		syslog(LOG_ERR, errfmt, pair_id, pid, sig, signame, cause);
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
	socklen_t addrlen;
	pid_t pid;
	int len, sock;
	const char *fmt = "A new master (pair id: %ld) has come.";
	char token[TOKEN_SIZE];

	addrlen = sizeof(addr);
	sock = accept(mhub->fork_sock, (struct sockaddr *)&addr, &addrlen);
	if (sock == -1)
		die(1, "accept(2) failed");
	read_or_die(sock, token, sizeof(token));
	fi = find_fork_info_of_token(mhub, token);
	if (fi == NULL)
		die(1, "Cannot find token %s", token);
	assert(fi != NULL);
	syslog(LOG_INFO, fmt, fi->child_pair_id);

	pid = read_pid(sock, &len);
	master = create_master(mhub, fi->child_pair_id, pid, sock, sock);
	PREPEND_ITEM(&mhub->masters, master);

	REMOVE_ITEM(fi);
	free(fi);
}

static void
process_fork_return(struct mhub *mhub)
{
	struct fork_info *fi;
	struct payload *payload;
	payload_size_t buf_size, payload_size;
	pair_id_t pair_id;
	int rfd, wfd;
	char *buf;

	rfd = mhub->shub.rfd;
	pair_id = read_pair_id(rfd);
	buf_size = read_payload_size(rfd);
	buf = (char *)alloca(buf_size);
	read_or_die(rfd, buf, buf_size);

	fi = find_fork_info_of_pair_id(mhub, pair_id);
	assert(fi != NULL);

	payload = payload_create();
	payload_add_uint64(payload, TOKEN_SIZE);
	payload_add(payload, fi->token, TOKEN_SIZE);
	payload_size = payload_get_size(payload);

	wfd = find_master_of_pair_id(mhub, pair_id)->wfd;
	write_command(wfd, FORK_RETURN);
	write_payload_size(wfd, payload_size + buf_size);
	write_or_die(wfd, payload_get(payload), payload_size);
	write_or_die(wfd, buf, buf_size);

	payload_dispose(payload);

	wait_fork_child(mhub);
	process_fork_socket(mhub);
}

static void
process_shub(struct mhub *mhub)
{
	command_t cmd;
	const char *fmt = "processing %s from the slave hub.";

	cmd = read_command(mhub->shub.rfd);
	syslog(LOG_DEBUG, fmt, get_command_name(cmd));
	switch (cmd) {
	case SIGNALED:
		process_signaled(mhub, cmd);
		break;
	case FORK_RETURN:
		process_fork_return(mhub);
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
#include "dispatch_ret.inc"
		transfer_payload_to_master(mhub, cmd);
		break;
	default:
		diex(-1, "unknown command (%d) from the slave hub.", cmd);
	}
}

static void
dispose_master(struct master *master)
{

	REMOVE_ITEM(master);
	hub_close_fds_or_die(master->rfd, master->wfd);
	free(master);
}

static void
process_exit(struct mhub *mhub, struct master *master)
{
	pair_id_t pair_id;
	int _, status, wfd;

	status = read_int32(master->rfd, &_);
	pair_id = master->pair_id;
	syslog(LOG_DEBUG, "EXIT_CALL: pair_id=%ld, status=%d", pair_id, status);

	wfd = mhub->shub.wfd;
	write_command(wfd, EXIT_CALL);
	write_pair_id(wfd, pair_id);
	write_int32(wfd, status);

	dispose_master(master);
}

static void
transfer_simple_command_from_master(struct mhub *mhub, struct master *master,
				    command_t cmd)
{
	pair_id_t pair_id;
	int wfd;

	pair_id = master->pair_id;
	syslog(LOG_DEBUG, "%s: pair_id=%ld", get_command_name(cmd), pair_id);

	wfd = mhub->shub.wfd;
	write_command(wfd, cmd);
	write_pair_id(wfd, pair_id);
}

static void
transfer_payload_from_master(struct mhub *mhub, struct master *master, command_t cmd)
{
	pair_id_t pair_id;
	int len, payload_size, rfd, wfd;
	char buf[FSYSCALL_BUFSIZE_INT32];
	const char *fmt = "%s: pair_id=%ld, payload_size=%d", *name;

	rfd = master->rfd;
	len = read_numeric_sequence(rfd, buf, array_sizeof(buf));
	payload_size = decode_int32(buf, len);

	name = get_command_name(cmd);
	pair_id = master->pair_id;
	syslog(LOG_DEBUG, fmt, name, pair_id, payload_size);

	wfd = mhub->shub.wfd;
	write_command(wfd, cmd);
	write_pair_id(wfd, pair_id);
	write_or_die(wfd, buf, len);
	transfer(rfd, wfd, payload_size);
}

static void
read_fork_call(struct mhub *mhub, struct master *master)
{
	int len, payload_size;
	char buf[FSYSCALL_BUFSIZE_PAYLOAD_SIZE];
	const char *fmt = "FORK_CALL: pair_id=%ld, payload_size=%d";

	len = read_numeric_sequence(master->rfd, buf, array_sizeof(buf));
	payload_size = decode_int32(buf, len);
	assert(payload_size == 0);

	syslog(LOG_DEBUG, fmt, master->pair_id, payload_size);
}

static void
write_fork_call(struct mhub *mhub, struct master *master, struct fork_info *fi)
{
	payload_size_t payload_size;
	int wfd;
	char buf[FSYSCALL_BUFSIZE_PAIR_ID];

	payload_size = encode_pair_id(fi->child_pair_id, buf, sizeof(buf));

	wfd = mhub->shub.wfd;
	write_command(wfd, FORK_CALL);
	write_pair_id(wfd, master->pair_id);
	write_payload_size(wfd, payload_size);
	write_or_die(wfd, buf, payload_size);
}

static void
process_fork_call(struct mhub *mhub, struct master *master)
{
	struct fork_info *fi;

	read_fork_call(mhub, master);

	fi = (struct fork_info *)malloc_or_die(sizeof(*fi));
	fi->parent_pair_id = master->pair_id;
	fi->child_pair_id = mhub->next_pair_id;
	hub_generate_token(fi->token, TOKEN_SIZE);
	mhub->next_pair_id++;
	PREPEND_ITEM(&mhub->fork_info, fi);

	write_fork_call(mhub, master, fi);
}

static void
process_master(struct mhub *mhub, struct master *master)
{
	command_t cmd;
	pair_id_t pair_id;
	const char *fmt = "unknown command (%d) from master (%ld)", *name;

	cmd = read_command(master->rfd);
	name = get_command_name(cmd);
	pair_id = master->pair_id;
	syslog(LOG_DEBUG, "processing %s from the master %ld.", name, pair_id);
	switch (cmd) {
	case EXIT_CALL:
		process_exit(mhub, master);
		break;
	case FORK_CALL:
		process_fork_call(mhub, master);
		break;
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
#include "dispatch_call.inc"
		transfer_payload_from_master(mhub, master, cmd);
		break;
	case POLL_END:
		transfer_simple_command_from_master(mhub, master, cmd);
		break;
	default:
		diex(-1, fmt, cmd, master->pair_id);
		/* NOTREACHED */
	}
}

static bool
compare_rfd(struct item *item, void *bonus)
{
	struct master *master;
	int *rfd;

	master = (struct master *)item;
	rfd = (int *)bonus;

	return (master->rfd == *rfd);
}

static struct master *
find_master_of_rfd(struct mhub *mhub, int rfd)
{
	struct item *item;

	item = list_search(&mhub->masters, compare_rfd, &rfd);
	assert(item != NULL);

	return ((struct master *)item);
}

static void
process_fd(struct mhub *mhub, int fd, fd_set *fds)
{
	struct master *master;

	if (!FD_ISSET(fd, fds))
		return;
	if (fd == mhub->shub.rfd) {
		process_shub(mhub);
		return;
	}

	master = find_master_of_rfd(mhub, fd);
	process_master(mhub, master);
}

static void
process_fds(struct mhub *mhub)
{
	struct master *master;
	int i, max_fd, n, nfds, rfd;
	fd_set fds, *pfds;

	pfds = &fds;
	FD_ZERO(pfds);
	rfd = mhub->shub.rfd;
	FD_SET(rfd, pfds);
	max_fd = rfd;

	master = (struct master *)FIRST_ITEM(&mhub->masters);
	while (!IS_LAST(master)) {
		rfd = master->rfd;
		FD_SET(rfd, pfds);
		max_fd = MAX(max_fd, rfd);
		master = (struct master *)ITEM_NEXT(master);
	}
	nfds = max_fd + 1;
	n = select(nfds, pfds, NULL, NULL, NULL);
	if (n == -1)
		die(-1, "select failed");
	for (i = 0; i < nfds; i++)
		process_fd(mhub, i, pfds);
}

static void
mainloop(struct mhub *mhub)
{
	while (!IS_EMPTY(&mhub->masters))
		process_fds(mhub);
}

static int
count_env(struct env *penv)
{
	struct env *p;
	int n = 0;

	for (p = penv; p != NULL; p = p->next)
		n++;

	return (n);
}

static const char **
build_envp(struct env *penv)
{
	struct env *p;
	int i, nenv;
	const char **envp;

	nenv = count_env(penv);
	envp = (const char **)malloc_or_die((nenv + 1) * sizeof(const char *));

	for (p = penv, i = 0; p != NULL; p = p->next, i++)
		envp[i] = p->pair;
	envp[i] = NULL;

	return (envp);
}

static void
free_env(struct env *penv)
{
	struct env *next, *p;

	for (p = penv; p != NULL; p = next) {
		next = p->next;
		free(p);
	}
}

static int
mhub_main(struct mhub *mhub, const char *fork_sock, int argc, char *argv[], struct env *penv)
{
	struct master *master;
	int hub2master[2], master2hub[2], rfd, syscall_num, wfd;
	pid_t pid;
	const char **envp, *verbose;

	syscall_num = find_syscall();

	pipe_or_die(hub2master);
	pipe_or_die(master2hub);

	pid = fork_or_die();
	if (pid == 0) {
		close_or_die(hub2master[W]);
		close_or_die(master2hub[R]);

		rfd = hub2master[R];
		wfd = master2hub[W];
		envp = build_envp(penv);
		exec_master(syscall_num, rfd, wfd, fork_sock, argc, argv, envp);
		/* NOTREACHED */
	}

	free_env(penv);

	verbose = getenv(FSYSCALL_ENV_VERBOSE);
	if ((verbose != NULL) && (strcmp(verbose, "1") == 0))
		printf("pid of fmaster=%d\n", pid);

	close_or_die(hub2master[R]);
	close_or_die(master2hub[W]);

	master = create_master(mhub, 0, pid, master2hub[R], hub2master[W]);
	PREPEND_ITEM(&mhub->masters, master);

	negotiate_version_with_shub(mhub);
	negotiate_version_with_master(master);
	write_pair_id(mhub->shub.wfd, master->pair_id);
	transport_fds(mhub->shub.rfd, master->wfd);

	mainloop(mhub);

	return (0);
}

static struct env *
create_env(const char *pair)
{
	struct env *penv;

	penv = (struct env *)malloc_or_die(sizeof(struct env));
	penv->pair = pair;

	return (penv);
}

int
main(int argc, char *argv[])
{
	struct option opts[] = {
		{ "env", required_argument, NULL, 'e' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	struct mhub mhub, *pmhub;
	struct env *p, *penv = NULL;
	int opt, status;
	const char *sock_path;
	char **args;

	pmhub = &mhub;
	openlog(argv[0], LOG_PID, LOG_USER);
	log_start_message(argc, argv);

	while ((opt = getopt_long(argc, argv, "+", opts, NULL)) != -1)
		switch (opt) {
		case 'e':
			p = create_env(optarg);
			p->next = penv;
			penv = p;
			break;
		case 'h':
			usage();
			return (0);
		case 'v':
			printf("fmhub %s\n", FSYSCALL_VERSION);
			return (0);
		default:
			usage();
			return (-1);
		}
	if (argc - optind < 4) {
		usage();
		return (-1);
	}

	args = &argv[optind];
	pmhub->shub.rfd = atoi_or_die(args[0], "rfd");
	pmhub->shub.wfd = atoi_or_die(args[1], "wfd");
	initialize_list(&pmhub->masters);
	pmhub->next_pair_id = 1;
	initialize_list(&pmhub->fork_info);

	sock_path = args[2];
	pmhub->fork_sock = hub_open_fork_socket(sock_path);
	status = mhub_main(pmhub, sock_path, argc - optind - 3, args + 3, penv);
	hub_close_fork_socket(pmhub->fork_sock);
	hub_unlink_socket(sock_path);
	log_graceful_exit(status);

	return (status);
}

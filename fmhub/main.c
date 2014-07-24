#include <sys/types.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <assert.h>
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
#include <fsyscall/private/pipe_or_die.h>

struct master {
	struct item item;
	pid_t pid;
	int rfd;
	int wfd;
};

struct mhub {
	struct connection shub;
	struct list masters;
};

struct env {
	struct env *next;
	const char *pair;
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
exec_master(int syscall_num, int rfd, int wfd, int argc, char *argv[], const char *envp[])
{
	char **args;
	int i;

	args = (char **)alloca(sizeof(char *) * (argc + 1));
	for (i = 0; i < argc; i++) {
		args[i] = (char *)alloca(sizeof(char) * (strlen(argv[i]) + 1));
		strcpy(args[i], argv[i]);
	}
	args[i] = NULL;

	syscall(syscall_num, rfd, wfd, args[0], args, envp);
	die(1, "fmaster_evecve failed");
	/* NOTREACHED */
}

static struct master *
find_master_of_pid(struct mhub *mhub, pid_t pid)
{
	struct master *master;

	master = (struct master *)FIRST_ITEM(&mhub->masters);
	while ((ITEM_NEXT(master) != NULL) && (master->pid != pid))
		master = (struct master *)ITEM_NEXT(master);
	assert(ITEM_NEXT(master) != NULL);

	return (master);
}

static void
transfer_payload_to_master(struct mhub *mhub, command_t cmd)
{
	struct master *master;
	uint32_t payload_size;
	pid_t pid;
	int payload_len, rfd, wfd;
	char payload_buf[FSYSCALL_BUFSIZE_UINT32];
	const char *fmt = "%s: pid=%d, payload_size=%u";
	const char *name;

	name = get_command_name(cmd);
	syslog(LOG_DEBUG, "processing %s.", name);

	rfd = mhub->shub.rfd;
	pid = read_pid(rfd);
	payload_len = read_numeric_sequence(
		rfd,
		payload_buf,
		array_sizeof(payload_buf));
	payload_size = decode_uint32(payload_buf, payload_len);

	syslog(LOG_DEBUG, fmt, name, pid, payload_size);

	master = find_master_of_pid(mhub, pid);
	wfd = master->wfd;
	write_command(wfd, cmd);
	write_or_die(wfd, payload_buf, payload_len);
	transfer(rfd, wfd, payload_size);
}

static void
process_shub(struct mhub *mhub)
{
	command_t cmd;

	cmd = read_command(mhub->shub.rfd);
	switch (cmd) {
	case RET_POLL:
	case RET_SELECT:
	case RET_CONNECT:
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
	close_or_die(master->rfd);
	close_or_die(master->wfd);
	free(master);
}

static void
process_exit(struct mhub *mhub, struct master *master)
{
	int _, status, wfd;
	pid_t pid;

	status = read_int32(master->rfd, &_);
	pid = master->pid;
	syslog(LOG_DEBUG, "CALL_EXIT: pid=%d, status=%d", pid, status);

	wfd = mhub->shub.wfd;
	write_command(wfd, CALL_EXIT);
	write_pid(wfd, pid);
	write_int32(wfd, status);

	dispose_master(master);
}

static void
transfer_payload_from_master(struct mhub *mhub, struct master *master, command_t cmd)
{
	pid_t pid;
	int len, payload_size, rfd, wfd;
	char buf[FSYSCALL_BUFSIZE_INT32];
	const char *fmt = "%s: pid=%d, payload_size=%d", *name;

	pid = master->pid;
	name = get_command_name(cmd);
	syslog(LOG_DEBUG, "processing %s from master %d.", name, pid);

	rfd = master->rfd;
	len = read_numeric_sequence(rfd, buf, array_sizeof(buf));
	payload_size = decode_int32(buf, len);

	syslog(LOG_DEBUG, fmt, name, pid, payload_size);

	wfd = mhub->shub.wfd;
	write_command(wfd, cmd);
	write_pid(wfd, pid);
	write_or_die(wfd, buf, len);
	transfer(rfd, wfd, payload_size);
}

static void
process_master(struct mhub *mhub, struct master *master)
{
	command_t cmd;
	pid_t pid;

	cmd = read_command(master->rfd);
	switch (cmd) {
	case CALL_EXIT:
		process_exit(mhub, master);
		break;
	case CALL_POLL:
	case CALL_SELECT:
	case CALL_CONNECT:
#include "dispatch_call.inc"
		transfer_payload_from_master(mhub, master, cmd);
		break;
	default:
		pid = master->pid;
		diex(-1, "unknown command (%d) from master (%d)", cmd, pid);
		/* NOTREACHED */
	}
}

static struct master *
find_master_of_rfd(struct mhub *mhub, int rfd)
{
	struct master *master;

	master = (struct master *)FIRST_ITEM(&mhub->masters);
	while ((ITEM_NEXT(master) != NULL) && (master->rfd != rfd))
		master = (struct master *)ITEM_NEXT(master);
	assert(ITEM_NEXT(master) != NULL);

	return (master);
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
	fd_set fds;

	FD_ZERO(&fds);

	rfd = mhub->shub.rfd;
	FD_SET(rfd, &fds);
	max_fd = rfd;

	master = (struct master *)FIRST_ITEM(&mhub->masters);
	while (ITEM_NEXT(master) != NULL) {
		rfd = master->rfd;
		FD_SET(rfd, &fds);
		max_fd = MAX(max_fd, rfd);
		master = (struct master *)ITEM_NEXT(master);
	}
	nfds = max_fd + 1;
	n = select(nfds, &fds, NULL, NULL, NULL);
	if (n == -1)
		die(-1, "select failed");
	for (i = 0; i < nfds; i++)
		process_fd(mhub, i, &fds);
}

static void
mainloop(struct mhub *mhub)
{
	while (FIRST_ITEM(&mhub->masters)->next != NULL)
		process_fds(mhub);
}

static void
log_new_master(struct master *master)
{
	const char *fmt = "new master: pid=%d, rfd=%d, wfd=%d";

	syslog(LOG_DEBUG, fmt, master->pid, master->rfd, master->wfd);
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
mhub_main(struct mhub *mhub, int argc, char *argv[], struct env *penv)
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
		exec_master(syscall_num, rfd, wfd, argc, argv, envp);
		/* NOTREACHED */
	}

	free_env(penv);

	verbose = getenv(FSYSCALL_ENV_VERBOSE);
	if ((verbose != NULL) && (strcmp(verbose, "1") == 0))
		printf("pid of fmaster=%d\n", pid);

	close_or_die(hub2master[R]);
	close_or_die(master2hub[W]);

	master = malloc_or_die(sizeof(*master));
	master->pid = pid;
	master->rfd = master2hub[R];
	master->wfd = hub2master[W];
	PREPEND_ITEM(&mhub->masters, master);
	log_new_master(master);

	negotiate_version_with_shub(mhub);
	negotiate_version_with_master(master);
	write_pid(mhub->shub.wfd, pid);
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
	struct mhub mhub;
	struct env *p, *penv = NULL;
	int opt, status;
	char **args;

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
	if (argc - optind < 3) {
		usage();
		return (-1);
	}

	args = &argv[optind];
	mhub.shub.rfd = atoi_or_die(args[0], "rfd");
	mhub.shub.wfd = atoi_or_die(args[1], "wfd");

	initialize_list(&mhub.masters);

	status = mhub_main(&mhub, argc - optind - 2, args + 2, penv);
	log_graceful_exit(status);

	return (status);
}

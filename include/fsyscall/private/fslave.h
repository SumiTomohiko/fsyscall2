#if !defined(FSYSCALL_PRIVATE_FSLAVE_H_INCLUDED)
#define FSYSCALL_PRIVATE_FSLAVE_H_INCLUDED

#include <sys/queue.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>

#include <fsyscall/private/command.h>

struct slave_thread;
struct dir_entries_cache;

struct slave {
	pthread_rwlock_t		fsla_lock;
	SLIST_HEAD(, slave_thread)	fsla_slaves;

	struct dir_entries_cache	*fsla_dir_entries_cache;
	sigset_t mask;	/* signal mask during system call */
	int sigr;	/* file descriptor for data from signal handler */
	char *fork_sock;
};

struct memory;

struct slave_thread {
	SLIST_ENTRY(slave_thread)	fsth_next;

	struct slave			*fsth_slave;
	SLIST_HEAD(, memory)		fsth_memory;
	int				fsth_rfd;
	int				fsth_wfd;
	bool				fsth_signal_watcher;
};

void die_if_payload_size_mismatched(int, int);
void return_int(struct slave_thread *, command_t, int, int);
void return_ssize(struct slave_thread *, command_t, ssize_t, int);
void resume_signal(struct slave_thread *, sigset_t *);
void suspend_signal(struct slave_thread *, sigset_t *);

void process_close(struct slave_thread *);

#endif

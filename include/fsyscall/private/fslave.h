#if !defined(FSYSCALL_PRIVATE_FSLAVE_H_INCLUDED)
#define FSYSCALL_PRIVATE_FSLAVE_H_INCLUDED

#include <signal.h>

#include <fsyscall/private/command.h>

struct memory;

struct slave {
	sigset_t mask;	/* signal mask during system call */
	int rfd;
	int wfd;
	int sigr;	/* file descriptor for data from signal handler */
	const char *fork_sock;
	struct memory	*fsla_memory;
};

void die_if_payload_size_mismatched(int, int);
void return_int(struct slave *, command_t, int, int);
void return_ssize(struct slave *, command_t, ssize_t, int);
void resume_signal(struct slave *, sigset_t *);
void suspend_signal(struct slave *, sigset_t *);

void process_close(struct slave *);

#endif

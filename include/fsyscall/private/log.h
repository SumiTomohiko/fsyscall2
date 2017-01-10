#if !defined(FSYSCALL_PRIVATE_LOG_H_INCLUDED)
#define FSYSCALL_PRIVATE_LOG_H_INCLUDED

void log_graceful_exit(int);
void log_start_message(int, char * const *);

void log_graceful_exit2(int, void (*)(int, const char *));
void log_start_message2(int, char * const *, void (*)(int, const char *));

#endif

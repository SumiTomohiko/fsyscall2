#if !defined(FSYSCALL_PRIVATE_DIE_H_INCLUDED)
#define FSYSCALL_PRIVATE_DIE_H_INCLUDED

void die(int, const char *, ...);
void die_with_message(int, const char *);
void diec(int, int, const char *, ...);
void diex(int, const char *, ...);

void __die_for_assertion(const char *, int, const char *);
void __build_asserting_message(const char *, ...);

#define	die_if_false(expr, msg)		do {			\
	if (!(expr)) {						\
		__build_asserting_message msg;			\
		__die_for_assertion(__FILE__, __LINE__, #expr);	\
	}							\
}while (0)

#endif

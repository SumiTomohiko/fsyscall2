#if !defined(FSYSCALL_PRIVATE_PAYLOAD_H_INCLUDED)
#define	FSYSCALL_PRIVATE_PAYLOAD_H_INCLUDED

#include <fsyscall/private/command.h>

struct payload;

struct payload	*payload_create();
void		payload_dispose(struct payload *);
void		payload_add(struct payload *, const char *, payload_size_t);
void		payload_add_uint64(struct payload *, uint64_t);
char 		*payload_get(struct payload *);
payload_size_t	payload_get_size(struct payload *);

#endif

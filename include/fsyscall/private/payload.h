#if !defined(FSYSCALL_PRIVATE_PAYLOAD_H_INCLUDED)
#define	FSYSCALL_PRIVATE_PAYLOAD_H_INCLUDED

#include <sys/types.h>
#include <sys/socket.h>

#include <fsyscall/private/command.h>

struct payload;

struct payload	*fsyscall_payload_create(void);
int		fsyscall_payload_dispose(struct payload *);
int		fsyscall_payload_add(struct payload *, const char *,
				     payload_size_t);
int		fsyscall_payload_add_int32(struct payload *, int32_t);
int		fsyscall_payload_add_uint8(struct payload *, uint8_t);
int		fsyscall_payload_add_uint32(struct payload *, uint32_t);
int		fsyscall_payload_add_uint64(struct payload *, uint64_t);
int		fsyscall_payload_add_sockaddr(struct payload *,
					      struct sockaddr *);
char 		*fsyscall_payload_get(struct payload *);
payload_size_t	fsyscall_payload_get_size(struct payload *);

#if !defined(KLD_MODULE)
struct payload	*payload_create();
void		payload_add(struct payload *, const char *, payload_size_t);
void		payload_add_uint8(struct payload *, uint8_t);
void		payload_add_uint32(struct payload *, uint32_t);
void		payload_add_uint64(struct payload *, uint64_t);
void		payload_add_sockaddr(struct payload *, struct sockaddr *);
#define	payload_dispose		fsyscall_payload_dispose
#define	payload_get		fsyscall_payload_get
#define	payload_get_size	fsyscall_payload_get_size
#endif

#endif

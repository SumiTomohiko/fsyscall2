#if !defined(FSYSCALL_PRIVATE_PAYLOAD_H_INCLUDED)
#define	FSYSCALL_PRIVATE_PAYLOAD_H_INCLUDED

#include <sys/types.h>
#include <sys/dirent.h>
#include <sys/event.h>
#include <sys/socket.h>

#include <fsyscall/private/command.h>

struct payload;

struct payload	*fsyscall_payload_create(void);
int		fsyscall_payload_dispose(struct payload *);
int		fsyscall_payload_add(struct payload *, const char *,
				     payload_size_t);
int		fsyscall_payload_add_int16(struct payload *, int16_t);
int		fsyscall_payload_add_int32(struct payload *, int32_t);
int		fsyscall_payload_add_int64(struct payload *, int64_t);
int		fsyscall_payload_add_uint8(struct payload *, uint8_t);
int		fsyscall_payload_add_uint16(struct payload *, uint16_t);
int		fsyscall_payload_add_uint32(struct payload *, uint32_t);
int		fsyscall_payload_add_uint64(struct payload *, uint64_t);
int		fsyscall_payload_add_dirent(struct payload *,
					    const struct dirent *);
int		fsyscall_payload_add_kevent(struct payload *, struct kevent *);
int		fsyscall_payload_add_sockaddr(struct payload *,
					      struct sockaddr *);
int		fsyscall_payload_add_string(struct payload *, const char *);
int		fsyscall_payload_add_sigset(struct payload *, sigset_t *);
int		fsyscall_payload_add_timeval(struct payload *,
					     const struct timeval *);
char 		*fsyscall_payload_get(struct payload *);
payload_size_t	fsyscall_payload_get_size(struct payload *);
#define	fsyscall_payload_add_int	fsyscall_payload_add_int32
#define	fsyscall_payload_add_long	fsyscall_payload_add_int64
#define	fsyscall_payload_add_short	fsyscall_payload_add_int16
#define	fsyscall_payload_add_uint	fsyscall_payload_add_uint32
#define	fsyscall_payload_add_ulong	fsyscall_payload_add_uint64
#define	fsyscall_payload_add_ushort	fsyscall_payload_add_uint16
#define	fsyscall_payload_add_socklen	fsyscall_payload_add_uint32
#define	fsyscall_payload_add_time	fsyscall_payload_add_int64
#define	fsyscall_payload_add_suseconds	fsyscall_payload_add_long

#if !defined(KLD_MODULE)
struct payload	*payload_create();
void		payload_add(struct payload *, const char *, payload_size_t);
void		payload_add_int16(struct payload *, int16_t);
void		payload_add_int32(struct payload *, int32_t);
void		payload_add_int64(struct payload *, int64_t);
void		payload_add_uint8(struct payload *, uint8_t);
void		payload_add_uint32(struct payload *, uint32_t);
void		payload_add_uint64(struct payload *, uint64_t);
void		payload_add_dirent(struct payload *, const struct dirent *);
void		payload_add_kevent(struct payload *, struct kevent *);
void		payload_add_sockaddr(struct payload *, struct sockaddr *);
void		payload_dump(const struct payload *);
#define	payload_add_long	payload_add_int64
#define	payload_add_int		payload_add_int32
#define	payload_add_short	payload_add_int16
#define	payload_add_socklen	payload_add_uint32
#define	payload_add_ssize	payload_add_int64
#define	payload_add_pid		payload_add_int32
#define	payload_add_uid		payload_add_uint32
#define	payload_add_gid		payload_add_uint32
#define	payload_dispose		fsyscall_payload_dispose
#define	payload_get		fsyscall_payload_get
#define	payload_get_size	fsyscall_payload_get_size
#endif

#endif

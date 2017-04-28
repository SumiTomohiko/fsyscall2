#if !defined(FSYSCALL_PRIVATE_FSLAVE_STREAM_H_INCLUDED)
#define FSYSCALL_PRIVATE_FSLAVE_STREAM_H_INCLUDED

#include <sys/types.h>

struct stream {
	const char	*st_p;
	const char	*st_end;
};

void		stream_init(struct stream *, const char *, size_t);

uint8_t		stream_get_uint8(struct stream *);
uint16_t	stream_get_uint16(struct stream *);
uint32_t	stream_get_uint32(struct stream *);
uint64_t	stream_get_uint64(struct stream *);
#define	stream_get_int8(st)	((int8_t)stream_get_uint8((st)))
#define	stream_get_int16(st)	((int16_t)stream_get_uint16((st)))
#define	stream_get_int32(st)	((int32_t)stream_get_uint32((st)))
#define	stream_get_int64(st)	((int64_t)stream_get_uint64((st)))
#define	stream_get_short	stream_get_int16
#define	stream_get_int		stream_get_int32
#define	stream_get_long		stream_get_int64
#define	stream_get_ushort	stream_get_uint16
#define	stream_get_uint		stream_get_uint32
#define	stream_get_ulong	stream_get_uint64
#define	stream_get_ssize	stream_get_int64
#define	stream_get_size		stream_get_uint64
#define	stream_get_socklen	stream_get_uint32
#define	stream_get_pid		stream_get_int32
#define	stream_get_time		stream_get_int64
#define	stream_get_susecond	stream_get_int64
void		stream_get(struct stream *, void *, size_t);

#endif

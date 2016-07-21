#include <sys/param.h>
#include <sys/queue.h>
#include <dirent.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <fsyscall/private/die.h>
#include <fsyscall/private/fslave/dir_entries_cache.h>
#include <fsyscall/private/malloc_or_die.h>

struct cache {
	SLIST_ENTRY(cache)	cache_next;
	pthread_mutex_t		cache_lock;
	int			cache_fd;
	int			cache_size;	/* available size of
						   cache_buf */
	int			cache_pos;	/* current position in
						   cache_buf */
	char			*cache_buf;
};

struct dir_entries_cache {
	SLIST_HEAD(, cache)	dec_cache;
	pthread_mutex_t		dec_lock;
};

#define	PTHREAD_MUTEX_INIT(mutex)	do {				\
	int error = pthread_mutex_init((mutex), NULL);			\
	if (error != 0) {						\
		const char *fmt = "%s:%u: pthread_mutex_init failed";	\
		diec(1, error, fmt, __FILE__, __LINE__);		\
	}								\
} while (0)

#define	PTHREAD_MUTEX_LOCK(mutex)	do {				\
	int error = pthread_mutex_lock((mutex));			\
	if (error != 0) {						\
		const char *fmt = "%s:%u: pthread_mutex_lock failed";	\
		diec(1, error, fmt, __FILE__, __LINE__);		\
	}								\
} while (0)

#define	PTHREAD_MUTEX_UNLOCK(mutex)	do {				\
	int error = pthread_mutex_unlock((mutex));			\
	if (error != 0) {						\
		const char *fmt = "%s:%u: pthread_mutex_unlock failed";	\
		diec(1, error, fmt, __FILE__, __LINE__);		\
	}								\
} while (0)

#define	PTHREAD_MUTEX_DESTROY(mutex)	do {				\
	int error = pthread_mutex_destroy((mutex));			\
	if (error != 0) {						\
		const char *fmt = "%s:%u pthread_mutex_destroy failed";	\
		diec(1, error, fmt, __FILE__, __LINE__);		\
	}								\
} while (0)

static struct cache *
get_cache(struct dir_entries_cache *dec, int fd)
{
	struct cache *cache;

	SLIST_FOREACH(cache, &dec->dec_cache, cache_next)
		if (cache->cache_fd == fd)
			return (cache);

	return (NULL);
}

void
dir_entries_cache_lock(struct dir_entries_cache *dec, int fd)
{
	pthread_mutex_t *lock;
	struct cache *cache;

	lock = &dec->dec_lock;
	PTHREAD_MUTEX_LOCK(lock);

	cache = get_cache(dec, fd);
	if (cache != NULL)
		goto exit;
	cache = (struct cache *)malloc_or_die(sizeof(*cache));
	SLIST_INSERT_HEAD(&dec->dec_cache, cache, cache_next);
	PTHREAD_MUTEX_INIT(&cache->cache_lock);
	cache->cache_fd = fd;
	cache->cache_size = cache->cache_pos = 0;
	cache->cache_buf = NULL;

exit:
	PTHREAD_MUTEX_LOCK(&cache->cache_lock);
	PTHREAD_MUTEX_UNLOCK(lock);
}

void
dir_entries_cache_unlock(struct dir_entries_cache *dec, int fd)
{
	struct cache *cache;

	cache = get_cache(dec, fd);
	die_if_false(cache != NULL, ("invalid fd: fd=%d", fd));
	PTHREAD_MUTEX_UNLOCK(&cache->cache_lock);
}

int
dir_entries_cache_get(struct dir_entries_cache *dec, int fd, char *buf,
		      int nbytes, int nentmax)
{
	/* The cache for fd must be locked */
	const struct dirent *dir;
	struct cache *cache;
	int i, size;
	uint16_t reclen;
	const char *pend, *qend;
	char *p, *q;

	cache = get_cache(dec, fd);
	die_if_false(cache != NULL, ("cannot find cache: fd=%d", fd));

	pend = cache->cache_buf + cache->cache_size;
	qend = buf + nbytes;
	for (i = 0, p = cache->cache_buf + cache->cache_pos, q = buf;
	     (i < nentmax) && (p < pend);
	     i++, p += reclen, q += reclen) {
		dir = (const struct dirent *)p;
		reclen = dir->d_reclen;
		if (qend <= q + reclen)
			break;
		memcpy(q, p, reclen);
	}

	size = (uintptr_t)q - (uintptr_t)buf;
	cache->cache_pos += size;

	return (size);
}

static const char *
seek_entry(char *buf, int nbytes, int index)
{
	const struct dirent *dir;
	int i;
	char *p, *pend;

	pend = buf + nbytes;
	for (i = 0, p = buf;
	     (i < index) && (p < pend);
	     i++, p += dir->d_reclen)
		dir = (const struct dirent *)p;

	return (p < pend ? p : NULL);
}

void
dir_entries_cache_put(struct dir_entries_cache *dec, int fd, char *buf,
		      int nbytes, int from)
{
	/* The cache for fd must be locked */
	struct cache *cache;
	size_t size;
	const char *begin;
	char *p;

	cache = get_cache(dec, fd);
	die_if_false(cache != NULL, ("cannot find cache: fd=%d", fd));
	die_if_false((cache->cache_buf == NULL)
			|| (cache->cache_pos < cache->cache_size),
		     ("invalid put operation: buf=%p, pos=%d, size=%d",
		      cache->cache_buf, cache->cache_pos, cache->cache_size));
	begin = seek_entry(buf, nbytes, from);
	if (begin == NULL)
		return;
	free(cache->cache_buf);
	size = (uintptr_t)(buf + nbytes) - (uintptr_t)begin;
	p = malloc_or_die(size);
	memcpy(p, begin, size);
	cache->cache_size = size;
	cache->cache_pos = 0;
	cache->cache_buf = p;
}

static void
dispose_cache(struct dir_entries_cache *dec, struct cache *cache)
{

	SLIST_REMOVE(&dec->dec_cache, cache, cache, cache_next);
	free(cache->cache_buf);
	PTHREAD_MUTEX_DESTROY(&cache->cache_lock);
	free(cache);
}

void
dir_entries_cache_close(struct dir_entries_cache *dec, int fd)
{
	pthread_mutex_t *lock;
	struct cache *cache;

	lock = &dec->dec_lock;
	PTHREAD_MUTEX_LOCK(lock);

	cache = get_cache(dec, fd);
	if (cache == NULL)
		goto exit;
	dispose_cache(dec, cache);

exit:
	PTHREAD_MUTEX_UNLOCK(lock);
}

void
dir_entries_cache_dispose(struct dir_entries_cache *dec)
{
	struct cache *cache, *tmp;

	SLIST_FOREACH_SAFE(cache, &dec->dec_cache, cache_next, tmp)
		dispose_cache(dec, cache);
	PTHREAD_MUTEX_DESTROY(&dec->dec_lock);
}

struct dir_entries_cache *
dir_entries_cache_create()
{
	struct dir_entries_cache *dec;

	dec = (struct dir_entries_cache *)malloc_or_die(sizeof(*dec));
	SLIST_INIT(&dec->dec_cache);
	PTHREAD_MUTEX_INIT(&dec->dec_lock);

	return (dec);
}

#if !defined(FSYSCALL_PRIVATE_FSLAVE_DIR_ENTRIES_CACHE_H_INCLUDED)
#define FSYSCALL_PRIVATE_FSLAVE_DIR_ENTRIES_CACHE_H_INCLUDED

struct dir_entries_cache	*dir_entries_cache_create();

void	dir_entries_cache_lock(struct dir_entries_cache *, int);
void	dir_entries_cache_unlock(struct dir_entries_cache *, int);
int	dir_entries_cache_get(struct dir_entries_cache *, int, char *, int,
			      int);
void	dir_entries_cache_put(struct dir_entries_cache *, int, char *, int,
			      int);
void	dir_entries_cache_close(struct dir_entries_cache *, int);

void	dir_entries_cache_dispose(struct dir_entries_cache *);

#endif

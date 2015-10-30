#include <sys/param.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/sysproto.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
mmap_master(struct thread *td, const struct fmaster_mmap_args *uap, int lfd)
{
	struct mmap_args a;

	memcpy(&a, uap, sizeof(a));
	a.fd = lfd;

	return (sys_mmap(td, &a));
}

static int
mmap_main(struct thread *td, struct fmaster_mmap_args *uap)
{
	enum fmaster_file_place place;
	int error, lfd;

	if ((uap->flags & (MAP_ANON | MAP_STACK)) != 0)
		return (sys_mmap(td, (struct mmap_args *)uap));

	error = fmaster_get_vnode_info(td, uap->fd, &place, &lfd);
	if (error != 0)
		return (error);
	if (place == FFP_MASTER)
		return (mmap_master(td, uap, lfd));

	return (EBADF);
}

static struct flag_definition protdefs[] = {
	DEFINE_FLAG(PROT_NONE),
	DEFINE_FLAG(PROT_READ),
	DEFINE_FLAG(PROT_WRITE),
	DEFINE_FLAG(PROT_EXEC)
};

static int nprotdefs = array_sizeof(protdefs);

static struct flag_definition flagdefs[] = {
	DEFINE_FLAG(MAP_ANON),
	DEFINE_FLAG(MAP_FIXED),
	DEFINE_FLAG(MAP_HASSEMAPHORE),
#if 0
	/* not supported */
	DEFINE_FLAG(MAP_INHERIT),
#endif
	DEFINE_FLAG(MAP_NOCORE),
	DEFINE_FLAG(MAP_NOSYNC),
	DEFINE_FLAG(MAP_PREFAULT_READ),
	DEFINE_FLAG(MAP_PRIVATE),
	DEFINE_FLAG(MAP_SHARED),
	DEFINE_FLAG(MAP_STACK)
};

static int nflagdefs = array_sizeof(flagdefs);

int
sys_fmaster_mmap(struct thread *td, struct fmaster_mmap_args *uap)
{
	struct timeval time_start;
	int error;
	const char *sysname = "mmap";
	char sprot[256], sflags[256];

	fmaster_chain_flags(sprot, sizeof(sprot), uap->prot, protdefs,
			    nprotdefs);
	fmaster_chain_flags(sflags, sizeof(sflags), uap->flags, flagdefs,
			    nflagdefs);
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: addr=%p, len=%lu, prot=%d (%s), flags=%d (%s)"
		    ", fd=%d, pos=%d",
		    sysname, uap->addr, uap->len, uap->prot, sprot, uap->flags,
		    sflags, uap->fd, uap->pos);
	microtime(&time_start);

	error = mmap_main(td, uap);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/time.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
fstatfs_main(struct thread *td, int fd, struct statfs *ubuf)
{
	struct statfs kbuf;
	enum fmaster_file_place place;
	int error, lfd;

	error = fmaster_get_vnode_info(td, fd, &place, &lfd);
	if (error != 0)
		return (error);
	switch (place) {
	case FFP_MASTER:
		return (kern_fstatfs(td, lfd, ubuf));
	case FFP_SLAVE:
		break;
	default:
		return (EBADF);
	}

	kbuf.f_version = STATFS_VERSION;
	kbuf.f_type = 0x35;
	kbuf.f_flags = MNT_EXPORTED | MNT_DEFEXPORTED | MNT_LOCAL | MNT_ROOTFS;
	kbuf.f_bsize = 4096;
	kbuf.f_iosize = 32768;
	kbuf.f_blocks = 0;
	kbuf.f_bfree = 0;
	kbuf.f_bavail = 0;
	kbuf.f_files = 0;
	kbuf.f_ffree = 0;
	kbuf.f_syncwrites = 0;
	kbuf.f_asyncwrites = 0;
	kbuf.f_syncreads = 0;
	kbuf.f_asyncreads = 0;
	kbuf.f_namemax = MAXPATHLEN;
	kbuf.f_owner = 0;
	kbuf.f_fsid.val[0] = 0;
	kbuf.f_fsid.val[1] = 0;
	strcpy(kbuf.f_fstypename, "ufs");
	strcpy(kbuf.f_mntfromname, "/dev/abababababa");
	strcpy(kbuf.f_mntonname, "/");
	error = copyout(&kbuf, ubuf, sizeof(kbuf));
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_fstatfs(struct thread *td, struct fmaster_fstatfs_args *uap)
{
	struct statfs *buf;
	struct timeval t;
	int error, fd;
	const char *sysname = "fstatfs";

	fd = uap->fd;
	buf = uap->buf;
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: fd=%d, buf=%p",
		    sysname, fd, buf);
	microtime(&t);

	error = fstatfs_main(td, fd, buf);

	fmaster_log_syscall_end(td, sysname, &t, error);

	return (error);
}

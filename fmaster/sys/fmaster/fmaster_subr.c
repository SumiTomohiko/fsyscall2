#include <sys/param.h>
#include <sys/cdefs.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rmlock.h>
#include <sys/select.h>
#include <sys/selinfo.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/sysent.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <machine/stdarg.h>

#include <fsyscall/private.h>
#include <fsyscall/private/command.h>
#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/payload.h>
#include <fsyscall/private/read_sockaddr.h>

/* Set 1 if you want to write log /tmp/fmaster.log.<pid> */
#define	LOG_TO_FILE	0

struct fmaster_memory {
	SLIST_ENTRY(fmaster_memory)	mem_next;
	char				mem_data[0];
};

SLIST_HEAD(memory_list, fmaster_memory);

struct fmaster_thread_data;
LIST_HEAD(thread_list, fmaster_thread_data);

typedef lwpid_t			fmaster_tid;

#define	DATA_TOKEN_SIZE	64

struct fmaster_thread_data {
	LIST_ENTRY(fmaster_thread_data)	ftd_list;

	fmaster_tid			ftd_tid;
	int				ftd_rfd;
	int				ftd_wfd;
	int				ftd_kq;		/* kqueue for rfd */
	size_t				ftd_rfdlen;	/* readable data length
							   in the buffer of rfd
							   */
	struct memory_list		ftd_memory;
	uint64_t			ftd_token_size;
	char				ftd_token[DATA_TOKEN_SIZE];
};

#define	THREAD_BUCKETS_NUM	(257)

struct fmaster_threads {
	struct rmlock		fth_lock;
	uma_zone_t		fth_allocator;
	struct thread_list	fth_threads[THREAD_BUCKETS_NUM];
};

struct fmaster_vnode {
	struct mtx		fv_lock;
	enum fmaster_file_place	fv_place;
	int			fv_local;
	int			fv_refcount;
	char			fv_desc[VNODE_DESC_LEN];
};

struct fmaster_file {
	struct fmaster_vnode	*ff_vnode;
	bool			ff_close_on_exec;
};

struct fmaster_data {
	/*
	 * fdata_files - What is this?
	 *
	 * A master process handles two kinds of file. One is file opened in the
	 * slave process, another one is file opened in the master process, like
	 * pipes. In some cases, a slave file may be same as a master fd. So, if
	 * a master process requests open(2), and the slave process successed
	 * the request, the fmaster kernel module returns a virtual fd. This
	 * virtual fd is index of fmaster_proc_data::fdata_files.
	 */
	struct fmaster_file	fdata_files[FILES_NUM];
	struct mtx		fdata_files_lock;
	uma_zone_t		fdata_vnodes;

	struct fmaster_threads	fdata_threads;

	pid_t			fdata_slave_pid;

	char fork_sock[MAXPATHLEN];

	int fdata_logfd;
};

MALLOC_DEFINE(M_FMASTER, "fdata", "emuldata of fmaster");

static void
vnode_dtor(void *mem, int size, void *arg)
{
#if 1
	struct fmaster_vnode *vnode;

	if (size < sizeof(struct fmaster_vnode))
		return;

	vnode = (struct fmaster_vnode *)mem;
	mtx_destroy(&vnode->fv_lock);
#endif
}

static int
vnode_ctor(void *mem, int size, void *arg, int flags)
{
	struct fmaster_vnode *vnode;

	if (size < sizeof(struct fmaster_vnode))
		return (EINVAL);

	vnode = (struct fmaster_vnode *)mem;
#if 1
	/*
	 * zone(9) is saying that I can initialize mutexes in vnode_init. But it
	 * causes crash. I do not why. mtx_init(9) in the constructor works.
	 */
	mtx_init(&vnode->fv_lock, "fvnode", NULL, MTX_DEF);
#endif
	vnode->fv_refcount = 1;

	return (0);
}

static int
vnode_init(void *mem, int size, int flags)
{
#if 0
	struct fmaster_vnode *vnode;

	if (size < sizeof(struct fmaster_vnode))
		return (EINVAL);

	vnode = (struct fmaster_vnode *)mem;
	mtx_init(&vnode->fv_lock, "fvnode", NULL, MTX_DEF);
#endif

	return (0);
}

static void
vnode_fini(void *mem, int size)
{
#if 0
	struct fmaster_vnode *vnode;

	if (size < sizeof(struct fmaster_vnode))
		return;

	vnode = (struct fmaster_vnode *)mem;
	mtx_destroy(&vnode->fv_lock);
#endif
}

static struct fmaster_data *
fmaster_proc_data_of_thread(struct thread *td)
{

	return ((struct fmaster_data *)(td->td_proc->p_emuldata));
}

int
fmaster_openlog(struct thread *td)
{
#if LOG_TO_FILE
	pid_t pid;
	int error;
	char logpath[256];

	pid = td->td_proc->p_pid;
	snprintf(logpath, sizeof(logpath), "/tmp/fmaster.log.%d", pid);
	error = kern_open(td, logpath, UIO_SYSSPACE, O_CREAT | O_WRONLY, 0644);
	if (error != 0) {
		log(LOG_ERR, "cannot open log: %s\n", logpath);
		return (error);
	}
	fmaster_proc_data_of_thread(td)->fdata_logfd = td->td_retval[0];
#endif

	return (0);
}

static int
initialize_threads(struct fmaster_threads *threads)
{
	int i;

	rm_init(&threads->fth_lock, "fthreads");
	threads->fth_allocator = uma_zcreate("fthreads",
					     sizeof(struct fmaster_thread_data),
					     NULL, NULL, NULL, NULL, 0,
					     M_WAITOK);
	for (i = 0; i < THREAD_BUCKETS_NUM; i++)
		LIST_INIT(&threads->fth_threads[i]);

	return (0);
}

static int
create_data(struct fmaster_data **pdata)
{
	struct fmaster_data *data;
	struct fmaster_file *file;
	int error, flags, i;

	flags = M_WAITOK;
	data = (struct fmaster_data *)malloc(sizeof(*data), M_FMASTER, flags);
	if (data == NULL)
		return (ENOMEM);

	for (i = 0; i < FILES_NUM; i++) {
		file = &data->fdata_files[i];
		file->ff_vnode = NULL;
		file->ff_close_on_exec = false;
	}
	mtx_init(&data->fdata_files_lock, "ffiles", NULL, MTX_DEF);
	data->fdata_vnodes = uma_zcreate("fvnodes",
					 sizeof(struct fmaster_vnode),
					 vnode_ctor, vnode_dtor, vnode_init,
					 vnode_fini, 0, flags);

	error = initialize_threads(&data->fdata_threads);
	if (error != 0)
		return (error);

	data->fdata_slave_pid = SLAVE_PID_UNKNOWN;
	data->fdata_logfd = -1;

	*pdata = data;

	return (0);
}

static int
hash_tid(fmaster_tid tid)
{

	return (tid % THREAD_BUCKETS_NUM);
}

static struct thread_list *
get_thread_bucket(struct fmaster_threads *threads, fmaster_tid tid)
{

	return (&threads->fth_threads[hash_tid(tid)]);
}

static int
add_thread(struct fmaster_data *data, fmaster_tid tid,
	   struct fmaster_thread_data **pthread)
{
	struct fmaster_thread_data *tdata;
	struct fmaster_threads *threads;
	struct rmlock *lock;
	struct thread_list *list;

	threads = &data->fdata_threads;
	tdata = (struct fmaster_thread_data *)uma_zalloc(threads->fth_allocator,
							 M_WAITOK);
	if (tdata == NULL)
		return (ENOMEM);
	tdata->ftd_tid = tid;
	tdata->ftd_rfd = tdata->ftd_wfd = tdata->ftd_kq = -1;
	tdata->ftd_rfdlen = 0;
	SLIST_INIT(&tdata->ftd_memory);
	tdata->ftd_token_size = 0;
	tdata->ftd_token[0] = '\0';

	lock = &threads->fth_lock;
	rm_wlock(lock);
	list = get_thread_bucket(threads, tid);
	LIST_INSERT_HEAD(list, tdata, ftd_list);
	rm_wunlock(lock);

	*pthread = tdata;

	return (0);
}

int
fmaster_create_data(struct thread *td, int rfd, int wfd, const char *fork_sock,
		    struct fmaster_data **pdata)
{
	struct fmaster_thread_data *thread;
	struct fmaster_data *data;
	size_t len;
	int error;

	error = create_data(&data);
	if (error != 0)
		return (error);
	error = add_thread(data, td->td_tid, &thread);
	if (error != 0)
		return (error);
	thread->ftd_rfd = rfd;
	thread->ftd_wfd = wfd;
	len = sizeof(data->fork_sock);
	error = copystr(fork_sock, data->fork_sock, len, NULL);
	if (error != 0)
		return (error);

	*pdata = data;

	return (0);
}

static int
add_forking_thread(struct fmaster_data *data, fmaster_tid tid,
		   const char *token, size_t token_size)
{
	struct fmaster_thread_data *thread;
	int error;

	if (sizeof(thread->ftd_token) < token_size)
		return (ENOMEM);

	error = add_thread(data, tid, &thread);
	if (error != 0)
		return (error);

	memcpy(thread->ftd_token, token, token_size);
	thread->ftd_token_size = token_size;

	return (0);
}

static int
fmaster_copy_data(struct thread *td, struct fmaster_data *dest)
{
	uma_zone_t zone;
	const struct fmaster_data *data;
	const struct fmaster_vnode *vnode;
	struct fmaster_vnode *newvnode;
	int error, i;

	data = fmaster_proc_data_of_thread(td);
	memcpy(dest->fork_sock, data->fork_sock, sizeof(data->fork_sock));

	fmaster_lock_file_table(td);

	zone = dest->fdata_vnodes;
	for (i = 0; i < FILES_NUM; i++) {
		vnode =	data->fdata_files[i].ff_vnode;
		if (vnode == NULL) {
			dest->fdata_files[i].ff_vnode = NULL;
			continue;
		}
		newvnode = (struct fmaster_vnode *)uma_zalloc(zone, M_WAITOK);
		if (newvnode == NULL) {
			error = ENOMEM;
			goto exit;
		}
		newvnode->fv_place = vnode->fv_place;
		newvnode->fv_local = vnode->fv_local;
		newvnode->fv_refcount = vnode->fv_refcount;
		strcpy(newvnode->fv_desc, vnode->fv_desc);
		dest->fdata_files[i].ff_vnode = newvnode;
	}

	error = 0;
exit:
	fmaster_unlock_file_table(td);

	return (error);
}

static struct fmaster_thread_data *
fmaster_thread_data_of_thread(struct thread *td)
{
	struct rm_priotracker *ptracker, tracker;
	struct fmaster_thread_data *thread_data;
	struct fmaster_threads *threads;
	struct fmaster_data *data;
	struct rmlock *lock;
	struct thread_list *list;
	fmaster_tid tid;

	tid = td->td_tid;

	data = fmaster_proc_data_of_thread(td);
	threads = &data->fdata_threads;
	lock = &threads->fth_lock;
	ptracker = &tracker;
	rm_rlock(lock, ptracker);

	list = get_thread_bucket(threads, tid);
	LIST_FOREACH(thread_data, list, ftd_list)
		if (thread_data->ftd_tid == tid)
			break;

	rm_runlock(lock, ptracker);

	KASSERT(thread_data != NULL, ("thread data not found: tid=%d", tid));

	return (thread_data);
}

pid_t
fmaster_get_slave_pid(struct thread *td)
{

	return (fmaster_proc_data_of_thread(td)->fdata_slave_pid);
}

void
fmaster_set_slave_pid(struct thread *td, pid_t slave_pid)
{

	fmaster_proc_data_of_thread(td)->fdata_slave_pid = slave_pid;
}

int
fmaster_create_data2(struct thread *td, pid_t slave_pid, lwpid_t tid,
		     const char *token, size_t token_size,
		     struct fmaster_data **pdata)
{
	struct fmaster_data *data;
	int error;

	error = create_data(&data);
	if (error != 0)
		return (error);
	error = fmaster_copy_data(td, data);
	if (error != 0)
		goto fail;
	data->fdata_slave_pid = slave_pid;
	error = add_forking_thread(data, tid, token, token_size);
	if (error != 0)
		goto fail;

	*pdata = data;

	return (0);

fail:
	fmaster_delete_data(data);

	return (error);
}

#define	SAVE_RETVAL(td, retval)		do {	\
	(retval)[0] = (td)->td_retval[0];	\
	(retval)[1] = (td)->td_retval[1];	\
} while (0)
#define	RESTORE_RETVAL(td, retval)	do {	\
	(td)->td_retval[0] = (retval)[0];	\
	(td)->td_retval[1] = (retval)[1];	\
} while (0)

void
fmaster_log(struct thread *td, int pri, const char *fmt, ...)
{
	struct fmaster_data *data;
	va_list ap;
	register_t retval[2];
	pid_t pid;
	int logfd, size;
	char buf[1024], msg[1024];

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	pid = td->td_proc->p_pid;
	size = snprintf(buf, sizeof(buf), "fmaster[%d]: %s\n", pid, msg);

	data = fmaster_proc_data_of_thread(td);
	logfd = data->fdata_logfd;
	if (logfd != -1) {
		SAVE_RETVAL(td, retval);
		fmaster_write(td, logfd, buf, size);
		RESTORE_RETVAL(td, retval);
	}

	log(pri, "%s", buf);
}

void
fmaster_delete_data(struct fmaster_data *data)
{
	struct fmaster_thread_data *tdata, *tmp;
	struct fmaster_threads *threads;
	struct thread_list *list;
	uma_zone_t zone;
	int i;

	threads = &data->fdata_threads;
	for (i = 0; i < THREAD_BUCKETS_NUM; i++) {
		list = &threads->fth_threads[i];
		LIST_FOREACH_SAFE(tdata, list, ftd_list, tmp)
			uma_zfree(threads->fth_allocator, tdata);
	}
	uma_zdestroy(threads->fth_allocator);
	rm_destroy(&threads->fth_lock);

	zone = data->fdata_vnodes;
	for (i = 0; i < FILES_NUM; i++)
		uma_zfree(zone, data->fdata_files[i].ff_vnode);
	uma_zdestroy(data->fdata_vnodes);
	mtx_destroy(&data->fdata_files_lock);
	free(data, M_FMASTER);
}

void
fmaster_lock_file_table(struct thread *td)
{
	struct fmaster_data *data;

	data = fmaster_proc_data_of_thread(td);
	mtx_lock(&data->fdata_files_lock);
}

void
fmaster_unlock_file_table(struct thread *td)
{
	struct fmaster_data *data;

	data = fmaster_proc_data_of_thread(td);
	mtx_unlock(&data->fdata_files_lock);
}

static struct fmaster_vnode *
fmaster_alloc_vnode(struct thread *td)
{
	uma_zone_t zone;
	struct fmaster_vnode *vnode;

	zone = fmaster_proc_data_of_thread(td)->fdata_vnodes;
	vnode = (struct fmaster_vnode *)uma_zalloc(zone, M_WAITOK);

	return (vnode);
}

#define	ENSURE_FILES_LOCK_OWNED(td)	do {\
	if (mtx_owned(&fmaster_proc_data_of_thread((td))->fdata_files_lock) == 0)\
		return (EDOOFUS);\
} while (0)

static int
unref_fd(struct thread *td, int fd, enum fmaster_file_place *place, int *lfd,
	 int *refcount)
{
	struct fmaster_data *data;
	struct fmaster_vnode *vnode;

	ENSURE_FILES_LOCK_OWNED(td);

	if ((fd < 0) || (FILES_NUM <= fd))
		return (EBADF);
	data = fmaster_proc_data_of_thread(td);
	vnode = data->fdata_files[fd].ff_vnode;
	if (vnode == NULL)
		return (EBADF);

	mtx_lock(&vnode->fv_lock);

	vnode->fv_refcount--;
	*place = vnode->fv_place;
	*lfd = vnode->fv_local;
	*refcount = vnode->fv_refcount;
	data->fdata_files[fd].ff_vnode = NULL;

	mtx_unlock(&vnode->fv_lock);

	if (*refcount == 0)
		uma_zfree(data->fdata_vnodes, vnode);

	return (0);
}

int
fmaster_unref_fd(struct thread *td, int fd, enum fmaster_file_place *place,
		 int *lfd, int *refcount)
{
	int error;

	fmaster_lock_file_table(td);
	error = unref_fd(td, fd, place, lfd, refcount);
	fmaster_unlock_file_table(td);

	return (error);
}

static struct fmaster_vnode *
fmaster_get_locked_vnode_of_fd(struct thread *td, int fd)
{
	struct fmaster_data *data;
	struct fmaster_vnode *vnode;

	if ((fd < 0) || (FILES_NUM <= fd))
		return (NULL);

	fmaster_lock_file_table(td);

	data = fmaster_proc_data_of_thread(td);
	vnode = data->fdata_files[fd].ff_vnode;
	if (vnode != NULL)
		mtx_lock(&vnode->fv_lock);

	fmaster_unlock_file_table(td);

	return (vnode);
}

static void
fmaster_unlock_vnode(struct thread *td, struct fmaster_vnode *vnode)
{

	mtx_unlock(&vnode->fv_lock);
}

long
fmaster_subtract_timeval(const struct timeval *t1, const struct timeval *t2)
{
	time_t diff;

	diff = t2->tv_sec - t1->tv_sec;

	return (1000000 * diff + (t2->tv_usec - t1->tv_usec));
}

void
fmaster_log_syscall_end(struct thread *td, const char *name,
			const struct timeval *t1, int error)
{
	static const char *strerror[] = {
		"no error",
		"EPERM",
		"ENOENT",
		"ESRCH",
		"EINTR",
		"EIO",
		"ENXIO",
		"E2BIG",
		"ENOEXEC",
		"EBADF",
		"ECHILD",
		"EDEADLK",
		"ENOMEM",
		"EACCES",
		"EFAULT",
		"ENOTBLK",
		"EBUSY",
		"EEXIST",
		"EXDEV",
		"ENODEV",
		"ENOTDIR",
		"EISDIR",
		"EINVAL",
		"ENFILE",
		"EMFILE",
		"ENOTTY",
		"ETXTBSY",
		"EFBIG",
		"ENOSPC",
		"ESPIPE",
		"EROFS",
		"EMLINK",
		"EPIPE",
		"EDOM",
		"ERANGE",
		"EAGAIN",
		"EINPROGRESS",
		"EALREADY",
		"ENOTSOCK",
		"EDESTADDRREQ",
		"EMSGSIZE",
		"EPROTOTYPE",
		"ENOPROTOOPT",
		"EPROTONOSUPPORT",
		"ESOCKTNOSUPPORT",
		"EOPNOTSUPP",
		"EPFNOSUPPORT",
		"EAFNOSUPPORT",
		"EADDRINUSE",
		"EADDRNOTAVAIL",
		"ENETDOWN",
		"ENETUNREACH",
		"ENETRESET",
		"ECONNABORTED",
		"ECONNRESET",
		"ENOBUFS",
		"EISCONN",
		"ENOTCONN",
		"ESHUTDOWN",
		"ETOOMANYREFS",
		"ETIMEDOUT",
		"ECONNREFUSED",
		"ELOOP",
		"ENAMETOOLONG",
		"EHOSTDOWN",
		"EHOSTUNREACH",
		"ENOTEMPTY",
		"EPROCLIM",
		"EUSERS",
		"EDQUOT",
		"ESTALE",
		"EREMOTE",
		"EBADRPC",
		"ERPCMISMATCH",
		"EPROGUNAVAIL",
		"EPROGMISMATCH",
		"EPROCUNAVAIL",
		"ENOLCK",
		"ENOSYS",
		"EFTYPE",
		"EAUTH",
		"ENEEDAUTH",
		"EIDRM",
		"ENOMSG",
		"EOVERFLOW",
		"ECANCELED",
		"EILSEQ",
		"ENOATTR",
		"EDOOFUS",
		"EBADMSG",
		"EMULTIHOP",
		"ENOLINK",
		"EPROTO",
		"ENOTCAPABLE",
		"ECAPMODE"
	};
	struct timeval t2;
	long delta;
	int retval;
	const char *fmt, *s;

	fmt = "%s: ended: retval[0]=%d, retval[1]=%d, error=%d (%s): %ld[usec]",

	microtime(&t2);
	delta = fmaster_subtract_timeval(t1, &t2);
	retval = td->td_retval[0];
	s = (0 <= error) && (error <= ELAST) ? strerror[error] : "invalid";
	fmaster_log(td, LOG_DEBUG, fmt,
		    name, td->td_retval[0], td->td_retval[1], error, s, delta);
}

int
fmaster_is_master_file(struct thread *td, const char *path)
{
	int i, ndirs, nfiles;
	const char *dirs[] = {
		"/lib/",
		"/usr/lib/",
		"/usr/local/etc/fonts/conf.d/",
		"/usr/local/etc/pango/",
		"/usr/local/lib/",
		"/usr/local/share/fonts/",
		"/usr/local/share/dbus-1/services/",
		"/var/db/fontconfig/",
	};
	const char *files[] = {
		"/usr/local/etc/dbus-1/session.conf",
		"/usr/local/etc/dbus-1/session.d",
		"/usr/local/share/dbus-1/services",
		"/dev/null",
		"/dev/urandom",
		"/etc/nsswitch.conf",
		"/usr/local/etc/fonts/fonts.conf",
		"/usr/local/share/applications/gedit.desktop",
		"/var/db/dbus/machine-id",
		"/var/run/ld-elf.so.hints"
	};
	const char *s;

	ndirs = array_sizeof(dirs);
	for (i = 0; i < ndirs; i++) {
		s = dirs[i];
		if (strncmp(path, s, strlen(s)) == 0)
			return (1);
	}
	nfiles = array_sizeof(files);
	for (i = 0; i < nfiles; i++)
		if (strcmp(path, files[i]) == 0)
			return (1);

	return (0);
}

static void
die(struct thread *td, const char *cause)
{

	fmaster_log(td, LOG_INFO, "die: %s", cause);
	exit1(td, 1);
}

struct kevent_bonus {
	const struct kevent *changelist;
	struct kevent *eventlist;
};

static int
kevent_copyout(void *arg, struct kevent *kevp, int count)
{
	struct kevent_bonus *bonus;

	bonus = (struct kevent_bonus *)arg;
	memcpy(bonus->eventlist, kevp, sizeof(kevp[0]) * count);
	bonus->eventlist += count;

	return (0);
}

static int
kevent_copyin(void *arg, struct kevent *kevp, int count)
{
	struct kevent_bonus *bonus;

	bonus = (struct kevent_bonus *)arg;
	memcpy(kevp, bonus->changelist, sizeof(kevp[0]) * count);
	bonus->changelist += count;

	return (0);
}

static int
wait_data(struct thread *td)
{
	struct fmaster_thread_data *thread_data;
	struct kevent kev;
	struct timespec timeout;
	struct kevent_copyops k_ops;
	struct kevent_bonus k_bonus;
	int error, kq;

	thread_data = fmaster_thread_data_of_thread(td);
	kq = thread_data->ftd_kq;
	timeout.tv_sec = 120;
	timeout.tv_nsec = 0;
	k_bonus.changelist = NULL;
	k_bonus.eventlist = &kev;
	k_ops.arg = &k_bonus;
	k_ops.k_copyin = NULL;
	k_ops.k_copyout = kevent_copyout;
	error = kern_kevent(td, kq, 0, 1, &k_ops, &timeout);
	if (error != 0)
		return (error);
	if (td->td_retval[0] == 0)
		return (ETIMEDOUT);
	thread_data->ftd_rfdlen += kev.data;

	return (0);
}

static int
do_readv(struct thread *td, int d, void *buf, size_t nbytes, int segflg)
{
	struct fmaster_thread_data *thread_data;
	struct uio auio;
	struct iovec aiov;
	int error;

	if (INT_MAX < nbytes)
		return (EINVAL);

	aiov.iov_base = buf;
	aiov.iov_len = nbytes;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbytes;
	auio.uio_segflg = segflg;

	error = 0;
	thread_data = fmaster_thread_data_of_thread(td);
	while (0 < auio.uio_resid) {
		if (thread_data->ftd_rfdlen == 0) {
			error = wait_data(td);
			if (error != 0)
				return (error);
		}
		error = kern_readv(td, d, &auio);
		if (error != 0)
			return (error);
		if (td->td_retval[0] == 0)
			die(td, "readv");
		thread_data->ftd_rfdlen -= td->td_retval[0];
	}

	return (error);
}

int
fmaster_read(struct thread *td, int d, void *buf, size_t nbytes)
{

	return do_readv(td, d, buf, nbytes, UIO_SYSSPACE);
}

static int
rs_read_socklen(struct rsopts *opts, socklen_t *socklen, int *len)
{
	struct thread *td = (struct thread *)opts->rs_bonus;
	int error;

	error = fmaster_read_socklen(td, socklen, len);

	return (error);
}

static int
rs_read_uint64(struct rsopts *opts, uint64_t *n, int *len)
{
	struct thread *td = (struct thread *)opts->rs_bonus;
	int error;

	error = fmaster_read_uint64(td, n, len);

	return (error);
}

static int
rs_read_uint8(struct rsopts *opts, uint8_t *n, int *len)
{
	struct thread *td = (struct thread *)opts->rs_bonus;
	int error;

	error = fmaster_read_uint8(td, n, len);

	return (error);
}

static int
rs_read(struct rsopts *opts, char *buf, int len)
{
	struct thread *td = (struct thread *)opts->rs_bonus;
	int error, rfd;

	rfd = fmaster_rfd_of_thread(td);
	error = fmaster_read(td, rfd, buf, len);

	return (error);
}

static void *
rs_malloc(struct rsopts *opts, size_t size)
{

	return malloc(size, M_TEMP, M_WAITOK | M_ZERO);
}

static void
rs_free(struct rsopts *opts, void *ptr)
{

	free(ptr, M_TEMP);
}

int
fmaster_read_sockaddr(struct thread *td, struct sockaddr_storage *addr,
		      int *len)
{
	struct rsopts opts;
	int error;

	opts.rs_bonus = td;
	opts.rs_read_socklen = rs_read_socklen;
	opts.rs_read_uint8 = rs_read_uint8;
	opts.rs_read_uint64 = rs_read_uint64;
	opts.rs_read = rs_read;
	opts.rs_malloc = rs_malloc;
	opts.rs_free = rs_free;

	error = fsyscall_read_sockaddr(&opts, addr, len);

	return (error);
}

static int
read_numeric_sequence(struct thread *td, int fd, char *buf, int bufsize, int *size)
{
	int error;
	char *p, *pend;

	pend = buf + bufsize;
	p = buf;
	error = fmaster_read(td, fd, p, sizeof(*p));
	while ((error == 0) && ((*p & 0x80) != 0) && (p + 1 < pend)) {
		p++;
		error = fmaster_read(td, fd, p, sizeof(*p));
	}
	if (error != 0)
		return (error);
	if ((*p & 0x80) != 0)
		return (EMSGSIZE);
	*size = (uintptr_t)p - (uintptr_t)buf + 1;
	return (0);
}

#define	IMPLEMENT_READ_X(type, name, bufsize, decode)		\
int								\
name(struct thread *td, type *dest, int *size)			\
{								\
	int error, fd;						\
	char buf[bufsize];					\
								\
	fd = fmaster_rfd_of_thread(td);				\
	error = read_numeric_sequence(				\
		td,						\
		fd,						\
		buf,						\
		array_sizeof(buf),				\
		size);						\
	if (error != 0)						\
		return (error);					\
								\
	return (decode(buf, *size, dest) != 0 ? EPROTO : 0);	\
}

IMPLEMENT_READ_X(
	int8_t,
	fmaster_read_int8,
	FSYSCALL_BUFSIZE_INT8,
	fsyscall_decode_int8)
IMPLEMENT_READ_X(
	int16_t,
	fmaster_read_int16,
	FSYSCALL_BUFSIZE_INT16,
	fsyscall_decode_int16)
IMPLEMENT_READ_X(
	int32_t,
	fmaster_read_int32,
	FSYSCALL_BUFSIZE_INT32,
	fsyscall_decode_int32)
IMPLEMENT_READ_X(
	int64_t,
	fmaster_read_int64,
	FSYSCALL_BUFSIZE_INT64,
	fsyscall_decode_int64)

int
fmaster_read_payload_size(struct thread *td, payload_size_t *dest)
{
	int _;

	return (fmaster_read_uint32(td, dest, &_));
}

int
fmaster_read_command(struct thread *td, command_t *dest)
{
	int _;

	return (fmaster_read_uint32(td, dest, &_));
}

static int
write_aio(struct thread *td, int d, const void *buf, size_t nbytes, enum uio_seg segflg)
{
	struct uio auio;
	struct iovec aiov;
	int error;

	if (INT_MAX < nbytes)
		return (EINVAL);

	/* Casting to uintptr_t is needed to escape the compiler warning. */
	aiov.iov_base = (void *)(uintptr_t)buf;
	aiov.iov_len = nbytes;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nbytes;
	auio.uio_segflg = segflg;

	error = 0;
	while (((error == 0) || (error == EINTR)) && (0 < auio.uio_resid))
		error = kern_writev(td, d, &auio);

	return (error);
}

int
fmaster_write_from_userspace(struct thread *td, int d, const void *buf, size_t nbytes)
{
	return (write_aio(td, d, buf, nbytes, UIO_USERSPACE));
}

int
fmaster_write(struct thread *td, int d, const void *buf, size_t nbytes)
{
	return (write_aio(td, d, buf, nbytes, UIO_SYSSPACE));
}

int
fmaster_rfd_of_thread(struct thread *td)
{
	return (fmaster_thread_data_of_thread(td)->ftd_rfd);
}

int
fmaster_wfd_of_thread(struct thread *td)
{
	return (fmaster_thread_data_of_thread(td)->ftd_wfd);
}

#define	IMPLEMENT_WRITE_X(type, name, bufsize, encode)	\
int							\
name(struct thread *td, type n)				\
{							\
	int len, wfd;					\
	char buf[bufsize];				\
							\
	len = encode(n, buf, array_sizeof(buf));	\
	if (len < 0)					\
		return (EMSGSIZE);			\
	wfd = fmaster_wfd_of_thread(td);		\
	return (fmaster_write(td, wfd, buf, len));	\
}

IMPLEMENT_WRITE_X(
		command_t,
		fmaster_write_command,
		FSYSCALL_BUFSIZE_COMMAND,
		fsyscall_encode_command)
IMPLEMENT_WRITE_X(
		int32_t,
		fmaster_write_int32,
		FSYSCALL_BUFSIZE_INT32,
		fsyscall_encode_int32)

int
fmaster_execute_return_optional32(struct thread *td, command_t expected_cmd, int (*callback)(struct thread *, int, payload_size_t *, void *), void *bonus)
{
	payload_size_t actual_payload_size, optional_payload_size, payload_size;
	command_t cmd;
	int errnum, errnum_len, error, retval, retval_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (expected_cmd != cmd) {
		fmaster_log(td, LOG_ERR,
			    "command mismatched: expected=%d, actual=%d",
			    expected_cmd, cmd);
		return (EPROTO);
	}
	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);
	error = fmaster_read_int(td, &retval, &retval_len);
	if (error != 0)
		return (error);

	if (retval == -1) {
		error = fmaster_read_int32(td, &errnum, &errnum_len);
		if (error != 0)
			return (error);
		actual_payload_size = retval_len + errnum_len;
		if (payload_size != actual_payload_size) {
			fmaster_log(td, LOG_ERR,
				    "payload size mismatched: expected=%d, actu"
				    "al=%d",
				    payload_size, actual_payload_size);
			return (EPROTO);
		}
		return (errnum);
	}

	error = callback(td, retval, &optional_payload_size, bonus);
	if (error != 0)
		return (error);

	actual_payload_size = retval_len + optional_payload_size;
	if (payload_size != actual_payload_size) {
		fmaster_log(td, LOG_ERR,
			    "payload size mismatched: expected=%d, actual=%d",
			    payload_size, actual_payload_size);
		return (EPROTO);
	}

	td->td_retval[0] = retval;

	return (0);
}

int
fmaster_execute_return_generic32(struct thread *td, command_t expected_cmd)
{
	/**
	 * TODO: fmaster_execute_return_generic32 is very similar to
	 * fmaster_execute_return_generic64.
	 */
	int32_t ret;
	command_t cmd;
	uint32_t payload_size;
	int errnum, errnum_len, error, ret_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != expected_cmd)
		return (EPROTO);

	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_int32(td, &ret, &ret_len);
	if (error != 0)
		return (error);
	if (ret != -1) {
		if (payload_size != ret_len)
			return (EPROTO);
		td->td_retval[0] = ret;
		return (0);
	}

	error = fmaster_read_int32(td, &errnum, &errnum_len);
	if (error != 0)
		return (error);
	if (payload_size != ret_len + errnum_len)
		return (EPROTO);
	return (errnum);
}

static int
get_vfd_of_lfd(struct thread *td, enum fmaster_file_place place, int lfd,
	       int *vfd)
{
	struct fmaster_vnode *vnode;
	struct fmaster_file *file, *files;
	int error, i;

	fmaster_lock_file_table(td);

	files = fmaster_proc_data_of_thread(td)->fdata_files;
	for (i = 0; i < FILES_NUM; i++) {
		file = &files[i];
		if (file == NULL)
			continue;
		vnode = file->ff_vnode;
		if ((vnode->fv_place != place) || (vnode->fv_local != lfd))
			continue;
		*vfd = i;
		break;
	}
	error = i < FILES_NUM ? 0 : EBADF;

	fmaster_unlock_file_table(td);

	return (error);
}

int
fmaster_fd_of_master_fd(struct thread *td, int master_fd, int *vfd)
{

	return (get_vfd_of_lfd(td, FFP_MASTER, master_fd, vfd));
}

int
fmaster_fd_of_slave_fd(struct thread *td, int slave_fd, int *vfd)
{

	return (get_vfd_of_lfd(td, FFP_SLAVE, slave_fd, vfd));
}

int
fmaster_execute_return_generic64(struct thread *td, command_t expected_cmd)
{
	int64_t ret;
	command_t cmd;
	uint32_t payload_size;
	int errnum, errnum_len, error, ret_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != expected_cmd)
		return (EPROTO);

	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_int64(td, &ret, &ret_len);
	if (error != 0)
		return (error);
	if (ret != -1) {
		if (payload_size != ret_len)
			return (EPROTO);
		td->td_retval[0] = ret & UINT32_MAX;
		td->td_retval[1] = ret >> 32;
		return (0);
	}

	error = fmaster_read_int32(td, &errnum, &errnum_len);
	if (error != 0)
		return (error);
	if (payload_size != ret_len + errnum_len)
		return (EPROTO);
	return (errnum);
}

int
fmaster_read_to_userspace(struct thread *td, int d, void *buf, size_t nbytes)
{

	return do_readv(td, d, buf, nbytes, UIO_USERSPACE);
}

static int
find_unused_fd(struct thread *td, int *fd)
{
	struct fmaster_file *files;
	int i;

	ENSURE_FILES_LOCK_OWNED(td);

	files = fmaster_proc_data_of_thread(td)->fdata_files;
	for (i = 0; i < FILES_NUM; i++)
		if (files[i].ff_vnode == NULL) {
			*fd = i;
			return (0);
		}

	return (EMFILE);
}

const char *
fmaster_str_of_place(enum fmaster_file_place place)
{

	switch (place) {
	case FFP_MASTER:
		return "master";
	case FFP_SLAVE:
		return "slave";
	default:
		return "invalid";
	}
}

static int
fmaster_register_fd_at(struct thread *td, enum fmaster_file_place place,
		       int lfd, int vfd, const char *desc)
{
	struct fmaster_vnode *vnode;
	struct fmaster_file *file;
	const char *fmt = "fd %d on %s has been registered as fd %d";

	if ((vfd < 0) || (FILES_NUM <= vfd))
		return (EBADF);

	ENSURE_FILES_LOCK_OWNED(td);

	file = &fmaster_proc_data_of_thread(td)->fdata_files[vfd];
	if (file->ff_vnode != NULL)
		return (EBADF);

	vnode = fmaster_alloc_vnode(td);
	if (vnode == NULL)
		return (ENOMEM);
	vnode->fv_place = place;
	vnode->fv_local = lfd;
	strlcpy(vnode->fv_desc, desc, sizeof(vnode->fv_desc));
	file->ff_vnode = vnode;
	file->ff_close_on_exec = false;

	fmaster_log(td, LOG_DEBUG, fmt, lfd, fmaster_str_of_place(place), vfd);

	return (0);
}

int
fmaster_register_file(struct thread *td, enum fmaster_file_place place,
		      int lfd, int *vfd, const char *desc)
{
	int error;

	fmaster_lock_file_table(td);

	error = find_unused_fd(td, vfd);
	if (error != 0)
		goto exit;
	error = fmaster_register_fd_at(td, place, lfd, *vfd, desc);
	if (error != 0)
		goto exit;

exit:
	fmaster_unlock_file_table(td);

	return (error);
}

int
fmaster_return_fd(struct thread *td, enum fmaster_file_place place, int lfd,
		  const char *desc)
{
	int error, virtual_fd;

	error = fmaster_register_file(td, place, lfd, &virtual_fd, desc);
	if (error != 0)
		return (error);

	td->td_retval[0] = virtual_fd;

	return (0);
}

static int
execute_accept_call(struct thread *td, command_t call_command, int s,
		    socklen_t namelen)
{
	struct payload *payload;
	payload_size_t payload_size;
	int error, wfd;
	const char *buf;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);

	error = fsyscall_payload_add_int(payload, s);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_socklen(payload, namelen);
	if (error != 0)
		goto exit;

	error = fmaster_write_command(td, call_command);
	if (error != 0)
		goto exit;
	payload_size = fsyscall_payload_get_size(payload);
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		goto exit;
	wfd = fmaster_wfd_of_thread(td);
	buf = fsyscall_payload_get(payload);
	error = fmaster_write(td, wfd, buf, payload_size);
	if (error != 0)
		goto exit;

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
execute_accept_return(struct thread *td, command_t return_command,
		      struct sockaddr_storage *addr, socklen_t *namelen)
{
	payload_size_t actual_payload_size, payload_size;
	command_t cmd;
	int addr_len, errnum, errnum_len, error, namelen_len, retval;
	int retval_len;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != return_command)
		return (EPROTO);

	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_int(td, &retval, &retval_len);
	if (error != 0)
		return (error);
	actual_payload_size = retval_len;
	if (retval == -1) {
		error = fmaster_read_int(td, &errnum, &errnum_len);
		if (error != 0)
			return (error);
		actual_payload_size += errnum_len;
		if (payload_size != actual_payload_size)
			return (EPROTO);
		return (errnum);
	}

	error = fmaster_read_socklen(td, namelen, &namelen_len);
	if (error != 0)
		return (error);
	actual_payload_size += namelen_len;
	error = fmaster_read_sockaddr(td, addr, &addr_len);
	if (error != 0)
		return (error);
	actual_payload_size += addr_len;
	if (payload_size != actual_payload_size)
		return (EPROTO);
	td->td_retval[0] = retval;

	return (0);
}

int
fmaster_get_vnode_info(struct thread *td, int fd,
		       enum fmaster_file_place *place, int *lfd)
{
	struct fmaster_vnode *vnode;

	vnode = fmaster_get_locked_vnode_of_fd(td, fd);
	if (vnode == NULL)
		return (EBADF);

	if (place != NULL)
		*place = vnode->fv_place;
	if (lfd != NULL)
		*lfd = vnode->fv_local;

	fmaster_unlock_vnode(td, vnode);

	return (0);
}

static int
accept_main(struct thread *td, command_t call_command, command_t return_command,
	    int s, struct sockaddr *name, socklen_t *namelen)
{
	struct sockaddr_storage addr;
	socklen_t actual_namelen, knamelen, len;
	enum fmaster_file_place place;
	int error, fd;

	error = fmaster_get_vnode_info(td, s, &place, &fd);
	if (error != 0)
		return (error);
	if (place != FFP_SLAVE)
		return (EPERM);
	knamelen = sizeof(addr);
	error = execute_accept_call(td, call_command, fd, knamelen);
	if (error != 0)
		return (error);
	error = execute_accept_return(td, return_command, &addr,
				      &actual_namelen);
	if (error != 0)
		return (error);
	if ((name != NULL) && (namelen != NULL)) {
		error = copyin(namelen, &len, sizeof(len));
		if (error != 0)
			return (error);
		error = copyout(&addr, name, MIN(len, actual_namelen));
		if (error != 0)
			return (error);
		error = copyout(&actual_namelen, namelen,
				sizeof(actual_namelen));
		if (error != 0)
			return (error);
	}

	return (0);
}

int
fmaster_execute_accept_protocol(struct thread *td, const char *command,
				command_t call_command,
				command_t return_command, int s,
				struct sockaddr *name, socklen_t *namelen)
{
	struct timeval time_start;
	int error;
	const char *fmt = "%s: started: s=%d, name=%p, namelen=%p";

	fmaster_log(td, LOG_DEBUG, fmt, command, s, name, namelen);
	microtime(&time_start);

	error = accept_main(td, call_command, return_command, s, name, namelen);

	fmaster_log_syscall_end(td, command, &time_start, error);

	return (error);
}

static int
execute_connect_call(struct thread *td, command_t call_command, int s,
		     struct sockaddr *name, socklen_t namelen)
{
	struct sockaddr_storage addr;
	struct payload *payload;
	payload_size_t payload_size;
	enum fmaster_file_place place;
	int error, slave_fd, wfd;
	const char *buf;

	error = fmaster_get_vnode_info(td, s, &place, &slave_fd);
	if (error != 0)
		return (error);
	if (place != FFP_SLAVE)
		return (EPERM);

	if (sizeof(addr) < namelen)
		return (EINVAL);
	bzero(&addr, sizeof(addr));
	error = copyin(name, &addr, namelen);
	if (error != 0)
		return (error);
	if (addr.ss_family != AF_LOCAL)
		return (EPROTONOSUPPORT);

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);

	error = fsyscall_payload_add_int32(payload, slave_fd);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_uint32(payload, namelen);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_sockaddr(payload,
					      (struct sockaddr *)&addr);
	if (error != 0)
		goto exit;

	error = fmaster_write_command(td, call_command);
	if (error != 0)
		goto exit;
	payload_size = fsyscall_payload_get_size(payload);
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		goto exit;
	wfd = fmaster_wfd_of_thread(td);
	buf = fsyscall_payload_get(payload);
	error = fmaster_write(td, wfd, buf, payload_size);
	if (error != 0)
		goto exit;

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
connect_main(struct thread *td, command_t call_command,
	     command_t return_command, int s, struct sockaddr *name,
	     socklen_t namelen)
{
	int error;

	error = execute_connect_call(td, call_command, s, name, namelen);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_generic32(td, return_command);
	if (error != 0)
		return (error);

	return (0);
}

int
fmaster_execute_connect_protocol(struct thread *td, const char *command,
				 command_t call_command,
				 command_t return_command, int s,
				 struct sockaddr *name, socklen_t namelen)
{
	struct timeval time_start;
	int error;
	const char *fmt = "%s: started: s=%d, name=%p, namelen=%d";

	fmaster_log(td, LOG_DEBUG, fmt, command, s, name, namelen);
	microtime(&time_start);

	error = connect_main(td, call_command, return_command, s, name,
			     namelen);

	fmaster_log_syscall_end(td, command, &time_start, error);

	return (error);
}

static int
fmaster_initialize_kqueue(struct thread *td,
			  struct fmaster_thread_data *thread_data)
{
	struct kevent kev;
	struct kevent_copyops k_ops;
	struct kevent_bonus k_bonus;
	pid_t pid;
	int error, kq;
	u_short flags;
	const char *fmt;

	pid = td->td_proc->p_pid;
	error = sys_kqueue(td, NULL);
	if (error != 0) {
		fmt = "sys_kqueue failed: error=%d";
		fmaster_log(td, LOG_DEBUG, fmt, error);
		return (error);
	}
	kq = td->td_retval[0];

	flags = EV_ADD | EV_ENABLE | EV_CLEAR;
	EV_SET(&kev, thread_data->ftd_rfd, EVFILT_READ, flags, 0, 0, NULL);
	k_bonus.changelist = &kev;
	k_bonus.eventlist = NULL;
	k_ops.arg = &k_bonus;
	k_ops.k_copyout = NULL;
	k_ops.k_copyin = kevent_copyin;
	error = kern_kevent(td, kq, 1, 0, &k_ops, NULL);
	if (error != 0) {
		fmt = "kern_kevent failed: error=%d";
		fmaster_log(td, LOG_DEBUG, fmt, error);
		return (error);
	}

	thread_data->ftd_kq = kq;
	thread_data->ftd_rfdlen = 0;

	return (0);
}

int
fmaster_initialize_kqueues(struct thread *td, struct fmaster_data *data)
{
	struct fmaster_thread_data *tdata;
	struct fmaster_threads *threads;
	struct rmlock *lock;
	int error, i;

	threads = &data->fdata_threads;
	lock = &threads->fth_lock;
	rm_wlock(lock);

	for (i = 0; i < THREAD_BUCKETS_NUM; i++)
		LIST_FOREACH(tdata, &threads->fth_threads[i], ftd_list) {
			error = fmaster_initialize_kqueue(td, tdata);
			if (error != 0)
				return (error);
		}

	rm_wunlock(lock);

	return (0);
}

static int
socket(struct thread *td, int *sock)
{
	struct socket_args args;
	int error;

	args.domain = PF_LOCAL;
	args.type = SOCK_STREAM;
	args.protocol = 0;
	error = sys_socket(td, &args);
	if (error != 0)
		return (error);

	*sock = td->td_retval[0];

	return (0);
}

#define SUN_LEN(su) \
	(sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))

static int
connect(struct thread *td, int sock)
{
	struct sockaddr_storage addr;
	struct sockaddr_un *paddr;
	int error;
	const char *path;

	paddr = (struct sockaddr_un *)&addr;
	paddr->sun_family = AF_LOCAL;
	path = fmaster_proc_data_of_thread(td)->fork_sock;
	error = copystr(path, paddr->sun_path, sizeof(paddr->sun_path), NULL);
	if (error != 0)
		return (error);
	paddr->sun_len = SUN_LEN(paddr);

	error = kern_connect(td, sock, (struct sockaddr *)paddr);
	if (error != 0)
		return (error);

	return (0);
}

static int
connect_to_mhub(struct thread *td)
{
	struct fmaster_thread_data *thread_data;
	struct fmaster_data *data;
	int error, pidlen, sock;
	char buf[FSYSCALL_BUFSIZE_PID];

	error = socket(td, &sock);
	if (error != 0)
		return (error);
	error = connect(td, sock);
	if (error != 0)
		return (error);

	thread_data = fmaster_thread_data_of_thread(td);
	thread_data->ftd_rfd = thread_data->ftd_wfd = sock;
	data = fmaster_proc_data_of_thread(td);
	error = fmaster_initialize_kqueues(td, data);
	if (error != 0)
		return (error);

	error = fmaster_write(td, sock, thread_data->ftd_token,
			      thread_data->ftd_token_size);
	if (error != 0)
		return (error);
	pidlen = fsyscall_encode_pid(td->td_proc->p_pid, buf, sizeof(buf));
	if (pidlen < 0)
		return (ENOMEM);
	error = fmaster_write(td, sock, buf, pidlen);
	if (error != 0)
		return (error);

	return (0);
}

void
fmaster_schedtail(struct thread *td)
{
	int error;
	const char *fmt = "cannot connect to mhub: error=%d";

	error = fmaster_openlog(td);
	if (error != 0)
		return;
	error = connect_to_mhub(td);
	if (error != 0)
		fmaster_log(td, LOG_ERR, fmt, error);
}

const char *
fmaster_get_sockopt_name(int optname)
{
	switch (optname) {
	case SO_DEBUG:
		return "SO_DEBUG";
	case SO_ACCEPTCONN:
		return "SO_ACCEPTCONN";
	case SO_REUSEADDR:
		return "SO_REUSEADDR";
	case SO_KEEPALIVE:
		return "SO_KEEPALIVE";
	case SO_DONTROUTE:
		return "SO_DONTROUTE";
	case SO_BROADCAST:
		return "SO_BROADCAST";
	case SO_USELOOPBACK:
		return "SO_USELOOPBACK";
	case SO_LINGER:
		return "SO_LINGER";
	case SO_OOBINLINE:
		return "SO_OOBINLINE";
	case SO_REUSEPORT:
		return "SO_REUSEPORT";
	case SO_TIMESTAMP:
		return "SO_TIMESTAMP";
	case SO_NOSIGPIPE:
		return "SO_NOSIGPIPE";
	case SO_ACCEPTFILTER:
		return "SO_ACCEPTFILTER";
	case SO_BINTIME:
		return "SO_BINTIME";
	case SO_NO_OFFLOAD:
		return "SO_NO_OFFLOAD";
	case SO_NO_DDP:
		return "SO_NO_DDP";
	case SO_SNDBUF:
		return "SO_SNDBUF";
	case SO_RCVBUF:
		return "SO_RCVBUF";
	case SO_SNDLOWAT:
		return "SO_SNDLOWAT";
	case SO_RCVLOWAT:
		return "SO_RCVLOWAT";
	case SO_SNDTIMEO:
		return "SO_SNDTIMEO";
	case SO_RCVTIMEO:
		return "SO_RCVTIMEO";
	case SO_ERROR:
		return "SO_ERROR";
	case SO_TYPE:
		return "SO_TYPE";
	case SO_LABEL:
		return "SO_LABEL";
	case SO_PEERLABEL:
		return "SO_PEERLABEL";
	case SO_LISTENQLIMIT:
		return "SO_LISTENQLIMIT";
	case SO_LISTENQLEN:
		return "SO_LISTENQLEN";
	case SO_LISTENINCQLEN:
		return "SO_LISTENINCQLEN";
	case SO_SETFIB:
		return "SO_SETFIB";
	case SO_USER_COOKIE:
		return "SO_USER_COOKIE";
	case SO_PROTOCOL:
	/* case SO_PROTOTYPE: */
		return "SO_PROTOCOL";
	default:
		break;
	}

	return "unknown option";
}

void
fmaster_chain_flags(char *buf, size_t bufsize, flag_t flags, struct flag_definition defs[], size_t ndefs)
{
	int i, len, size;
	const char *sep;

	buf[0] = '\0';
	len = 0;
	sep = "";
	for (i = 0; i < ndefs; i++) {
		if ((flags & defs[i].value) == 0)
			continue;
		size = bufsize - len;
		len += snprintf(&buf[len], size, "%s%s", sep, defs[i].name);
		sep = "|";
	}
	if (buf[0] == '\0')
		snprintf(buf, bufsize, "nothing");
}

/**
 * Writes a payload with its size.
 */
static int
fmaster_write_payload(struct thread *td, struct payload *payload)
{
	int error, wfd;
	payload_size_t payload_size;
	const char *buf;

	payload_size = fsyscall_payload_get_size(payload);
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		return (error);
	wfd = fmaster_wfd_of_thread(td);
	buf = fsyscall_payload_get(payload);
	error = fmaster_write(td, wfd, buf, payload_size);
	if (error != 0)
		return (error);

	return (0);
}

int
fmaster_write_payloaded_command(struct thread *td, command_t cmd,
				struct payload *payload)
{
	int error;

	error = fmaster_write_command(td, cmd);
	if (error != 0)
		return (error);
	error = fmaster_write_payload(td, payload);
	if (error != 0)
		return (error);

	return (0);
}

static int
execute_close_call(struct thread *td, int lfd)
{
	struct payload *payload;
	int error;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);
	error = fsyscall_payload_add_int(payload, lfd);
	if (error != 0)
		goto exit;

	error = fmaster_write_payloaded_command(td, CLOSE_CALL, payload);
	if (error != 0)
		goto exit;

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

int
fmaster_execute_close(struct thread *td, int lfd)
{
	int error;

	error = execute_close_call(td, lfd);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_generic32(td, CLOSE_RETURN);
	if (error != 0)
		return (error);

	return (0);
}

int
fmaster_dup2(struct thread *td, int from, int to)
{
	struct fmaster_data *data;
	struct fmaster_vnode *vnode;
	int error;

	if ((from < 0) || (FILES_NUM <= from))
		return (EBADF);
	if ((to < 0) || (FILES_NUM <= to))
		return (EBADF);

	fmaster_lock_file_table(td);

	data = fmaster_proc_data_of_thread(td);
	vnode = data->fdata_files[from].ff_vnode;
	if (vnode == NULL) {
		error = EBADF;
		goto exit;
	}

	mtx_lock(&vnode->fv_lock);
	data->fdata_files[to].ff_vnode = vnode;
	vnode->fv_refcount++;	/* FIXME: overflow */
	mtx_unlock(&vnode->fv_lock);

	error = 0;
exit:
	fmaster_unlock_file_table(td);

	return (error);
}

int
fmaster_dup(struct thread *td, int fd, int *newfd)
{
	struct fmaster_data *data;
	struct fmaster_vnode *vnode;
	int error;

	fmaster_lock_file_table(td);

	data = fmaster_proc_data_of_thread(td);
	vnode = data->fdata_files[fd].ff_vnode;
	if (vnode == NULL) {
		error = EBADF;
		goto exit;
	}
	mtx_lock(&vnode->fv_lock);

	error = find_unused_fd(td, newfd);
	if (error != 0)
		goto exit2;

	data->fdata_files[*newfd].ff_vnode = vnode;
	vnode->fv_refcount++;	/* FIXME: overflow */

	error = 0;
exit2:
	mtx_unlock(&vnode->fv_lock);
exit:
	fmaster_unlock_file_table(td);

	return (error);
}

static const char *
basename(const char *path)
{
	const char *p, *q;

	p = path;
	for (q = path; *q != '\0'; q++)
		if (*q == '/')
			p = q + 1;

	return (p);
}

void
_fmaster_dump_file_table(struct thread *td, const char *filename,
			 unsigned int lineno)
{
	struct fmaster_data *data;
	struct fmaster_vnode *vnode;
	register_t retval[2];
	pid_t pid;
	enum fmaster_file_place place;
	int error, i, lfd;
	const char *bname, *close_on_exec, *placestr;
	char dead_or_alive[64];

	fmaster_lock_file_table(td);

	pid = td->td_proc->p_pid;
	data = fmaster_proc_data_of_thread(td);
	for (i = 0; i < FILES_NUM; i++) {
		vnode = data->fdata_files[i].ff_vnode;
		if (vnode == NULL)
			continue;
		bname = basename(filename);
		place = vnode->fv_place;
		placestr = fmaster_str_of_place(place);
		lfd = vnode->fv_local;
		switch (place) {
		case FFP_MASTER:
			SAVE_RETVAL(td, retval);
			error = kern_fcntl(td, lfd, F_GETFD, 0);
			if (error == 0) {
				close_on_exec = td->td_retval[0] & FD_CLOEXEC
					? ", close_on_exec"
					: "";
				snprintf(dead_or_alive, sizeof(dead_or_alive),
					 " (alive%s)", close_on_exec);
			}
			else
				strlcpy(dead_or_alive, " (dead)",
					sizeof(dead_or_alive));
			RESTORE_RETVAL(td, retval);
			break;
		case FFP_SLAVE:
		default:
			dead_or_alive[0] = '\0';
			break;
		}
		fmaster_log(td, LOG_DEBUG,
			    "%s:%u: file[%d]: place=%s, local=%d%s, refcount=%d"
			    ", desc=%s",
			    bname, lineno, i, placestr, lfd, dead_or_alive,
			    vnode->fv_refcount, vnode->fv_desc);
	}

	fmaster_unlock_file_table(td);
}

int
fmaster_close_on_exec(struct thread *td)
{
	struct fmaster_data *data;
	struct fmaster_file *file;
	enum fmaster_file_place place;
	int error, i, lfd, newrefcount;

	fmaster_lock_file_table(td);

	data = fmaster_proc_data_of_thread(td);
	for (i = 0; i < FILES_NUM; i++) {
		file = &data->fdata_files[i];
		if (file->ff_vnode == NULL)
			continue;
		if (file->ff_close_on_exec) {
			error = unref_fd(td, i, &place, &lfd, &newrefcount);
			if (error != 0)
				goto exit;
			/* FIXME: A similar routine is in fmaster_close.c */
			if (0 < newrefcount)
				continue;
			switch (place) {
			case FFP_MASTER:
				error = kern_close(td, lfd);
				if (error != 0)
					goto exit;
				break;
			case FFP_SLAVE:
				error = fmaster_execute_close(td, lfd);
				if (error != 0)
					goto exit;
				break;
			default:
				error = EINVAL;
				goto exit;
			}
		}
	}

	error = 0;
exit:
	fmaster_unlock_file_table(td);

	return (error);
}

int
fmaster_set_close_on_exec(struct thread *td, int fd, bool close_on_exec)
{
	struct fmaster_file *file;
	int error;

	if ((fd < 0) || (FILES_NUM <= fd))
		return (EBADF);

	fmaster_lock_file_table(td);

	file = &fmaster_proc_data_of_thread(td)->fdata_files[fd];
	if (file->ff_vnode == NULL) {
		error = EBADF;
		goto exit;
	}
	file->ff_close_on_exec = close_on_exec;

	error = 0;
exit:
	fmaster_unlock_file_table(td);

	return (error);
}

int
fmaster_copyin_msghdr(struct thread *td, const struct msghdr *umsg,
		      struct msghdr *kmsg)
{
	struct iovec *iov;
	socklen_t namelen;
	int error, iovlen;
	void *name;

	error = copyin(umsg, kmsg, sizeof(*umsg));
	if (error != 0)
		return (error);

	namelen = kmsg->msg_namelen;
	if (kmsg->msg_name != NULL) {
		name = malloc(namelen, M_TEMP, M_WAITOK);
		if (name == NULL)
			return (ENOMEM);
		error = copyin(kmsg->msg_name, name, namelen);
		if (error != 0)
			goto fail;
		kmsg->msg_name = name;
	}

	iovlen = kmsg->msg_iovlen;
	error = copyiniov(kmsg->msg_iov, iovlen, &iov, EMSGSIZE);
	if (error != 0)
		goto fail;
	kmsg->msg_iov = iov;

	return (0);

fail:
	free(name, M_TEMP);

	return (error);
}

static const char *
dump(char *buf, size_t bufsize, const char *data, size_t datasize)
{
	static char chars[] = {
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		' ', '!', '"', '#', '$', '%', '&', '\'',
		'(', ')', '*', '+', ',', '-', '.', '/',
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', ':', ';', '<', '=', '>', '?',
		'@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
		'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
		'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
		'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
		'`', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
		'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
		'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
		'x', 'y', 'z', '{', '|', '}', '~', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?',
		'?', '?', '?', '?', '?', '?', '?', '?'
	};
	size_t i, len;
	const unsigned char *q;
	char *p;

	if (data == NULL)
		return ("null");

	len = MIN(bufsize - 1, datasize);
	for (i = 0, p = buf, q = data; i < len; i++, p++, q++)
		*p = chars[(unsigned int)*q];
	*p = '\0';

	return (buf);
}

static void
log_cmsgdata_creds(struct thread *td, const char *tag, struct cmsghdr *cmsghdr)
{
	struct cmsgcred *cred;
	int i, n;
	short ngroups;

	if (cmsghdr->cmsg_len < CMSG_LEN(sizeof(struct cmsgcred)))
		return;
	cred = (struct cmsgcred *)CMSG_DATA(cmsghdr);
#define	LOG(fmt, ...)	do {						\
	fmaster_log(td, LOG_DEBUG, "%s: " fmt, tag, __VA_ARGS__);	\
} while (0)
	LOG("cmcred_pid=%d", cred->cmcred_pid);
	LOG("cmcred_uid=%d", cred->cmcred_uid);
	LOG("cmcred_euid=%d", cred->cmcred_euid);
	LOG("cmcred_gid=%d", cred->cmcred_gid);
	ngroups = cred->cmcred_ngroups;
	LOG("cmcred_ngroups=%d", ngroups);
	n = MIN(ngroups, CMGROUP_MAX);
	for (i = 0; i < n; i++)
		LOG("cmcred_groups[%d]=%d", i, cred->cmcred_groups[i]);
#undef	LOG
}

int
fmaster_log_msghdr(struct thread *td, const char *tag, const struct msghdr *msg)
{
	struct cmsghdr *cmsghdr, *control;
	struct iovec *iov, *p;
	socklen_t len;
	int controllen, i, iovlen, level, namelen, *pend, *pfd, *pfds, type;
	const char *levelstr, *typestr;
	char buf[256];

#define	LOG(fmt, ...)	do {						\
	fmaster_log(td, LOG_DEBUG, "%s: " fmt, tag, __VA_ARGS__);	\
} while (0)
#define	DUMP(p, len)	dump(buf, sizeof(buf), (p), (len))
	namelen = msg->msg_namelen;
	LOG("msg->msg_name=%p", msg->msg_name);
	LOG("msg->msg_namelen=%d", namelen);
	iovlen = msg->msg_iovlen;
	iov = msg->msg_iov;
	for (i = 0; i < iovlen; i++) {
		p = &iov[i];
		LOG("msg->msg_iov[%d].iov_base=%s",
		    i, DUMP(p->iov_base, p->iov_len));
		LOG("msg->msg_iov[%d].iov_len=%d", i, p->iov_len);
	}
	LOG("msg->msg_iovlen=%d", iovlen);
	control = msg->msg_control;
	controllen = msg->msg_controllen;
	LOG("msg->msg_control=%s", DUMP(msg->msg_control, controllen));
	LOG("msg->msg_controllen=%d", controllen);
	for (cmsghdr = CMSG_FIRSTHDR(msg);
	     cmsghdr != NULL;
	     cmsghdr = CMSG_NXTHDR(msg, cmsghdr)) {
		level = cmsghdr->cmsg_level;
		type = cmsghdr->cmsg_type;
		switch (level) {
		case SOL_SOCKET:
			levelstr = "SOL_SOCKET";
			switch (type) {
			case SCM_CREDS:
				typestr = "SCM_CREDS";
				break;
			case SCM_RIGHTS:
				typestr = "SCM_RIGHTS";
				break;
			default:
				typestr = "invalid";
				break;
			}
			break;
		default:
			levelstr = typestr = "invalid";
			break;
		}
		LOG("cmsg_len=%d", cmsghdr->cmsg_len);
		LOG("cmsg_level=%d (%s)", level, levelstr);
		LOG("cmsg_type=%d (%s)", type, typestr);

		switch (level) {
		case SOL_SOCKET:
			switch (type) {
			case SCM_CREDS:
				log_cmsgdata_creds(td, tag, cmsghdr);
				break;
			case SCM_RIGHTS:
				pfds = (int *)CMSG_DATA(cmsghdr);
				len = cmsghdr->cmsg_len;
				pend = (int *)((char *)cmsghdr + len);
				for (pfd = pfds, i = 0; pfd < pend; pfd++, i++)
					LOG("fd[%d]=%d", i, pfds[i]);
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
	}
	LOG("msg->msg_flags=%d", msg->msg_flags);
#undef	DUMP
#undef	LOG

	return (0);
}

static struct malloc_type *memory_type = M_TEMP;

void *
fmaster_malloc(struct thread *td, size_t size)
{
	struct fmaster_thread_data *thread_data;
	struct fmaster_memory *memory;
	size_t totalsize;

	totalsize = sizeof(struct fmaster_memory) + size;
	memory = malloc(totalsize, memory_type, M_WAITOK);
	if (memory == NULL)
		return (NULL);

	thread_data = fmaster_thread_data_of_thread(td);
	SLIST_INSERT_HEAD(&thread_data->ftd_memory, memory, mem_next);

	return (&memory->mem_data[0]);
}

void
fmaster_freeall(struct thread *td)
{
	struct fmaster_thread_data *thread_data;
	struct fmaster_memory *memory, *next;

	thread_data = fmaster_thread_data_of_thread(td);
	SLIST_FOREACH_SAFE(memory, &thread_data->ftd_memory, mem_next, next)
		free(memory, memory_type);

	SLIST_INIT(&thread_data->ftd_memory);
}

int
fmaster_do_kevent(struct thread *td, const struct kevent *changelist,
		  int nchanges, struct kevent *eventlist, int *nevents,
		  const struct timespec *timeout)
{
	struct kevent_copyops k_ops;
	struct kevent_bonus k_bonus;
	int error, error2, kq;

	error = sys_kqueue(td, NULL);
	if (error != 0)
		return (error);
	kq = td->td_retval[0];

	k_bonus.changelist = changelist;
	k_bonus.eventlist = eventlist;
	k_ops.arg = &k_bonus;
	k_ops.k_copyout = kevent_copyout;
	k_ops.k_copyin = kevent_copyin;
	error = kern_kevent(td, kq, nchanges, *nevents, &k_ops, timeout);
	if (error != 0)
		goto exit;
	*nevents = td->td_retval[0];

exit:
	error2 = kern_close(td, kq);
	error = (error == 0) && (error2 != 0) ? error2 : error;

	return (error);
}

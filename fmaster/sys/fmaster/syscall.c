#include <sys/param.h>
#include <sys/errno.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>

SYSCTL_NODE(_kern, OID_AUTO, fmaster, CTLFLAG_RW, NULL, "");
SYSCTL_NODE(_debug, OID_AUTO, fmaster, CTLFLAG_RW, NULL, "");
SYSCTL_NODE(_security_bsd, OID_AUTO, fmaster, CTLFLAG_RW, NULL, "");

/* The following code came from /usr/src/sys/sys/syscall.h */
#define	PAD_(t)	(sizeof(register_t) <= sizeof(t) ? \
		0 : sizeof(register_t) - sizeof(t))
#if BYTE_ORDER == LITTLE_ENDIAN
#define	PADL_(t)	0
#define	PADR_(t)	PAD_(t)
#else
#define	PADL_(t)	PAD_(t)
#define	PADR_(t)	0
#endif

struct fmaster_execve_args {
	char rfd_l[PADL_(int)]; int rfd; char rfd_r[PADR_(int)];
	char wfd_l[PADL_(int)]; int wfd; char wfd_r[PADR_(int)];
	char fork_sock_l[PADL_(const char *)]; const char *fork_sock; char fork_sock_r[PADR_(const char *)];
	char path_l[PADL_(char *)]; char *path; char path_r[PADR_(char *)];
	char argv_l[PADL_(char **)]; char **argv; char argv_r[PADR_(char **)];
	char envp_l[PADL_(char **)]; char **envp; char envp_r[PADR_(char **)];
};

static int
negotiate_version(struct thread *td, int rfd, int wfd)
{
	int error;
	uint8_t request_ver, ver;

	request_ver = 0;
	error = fmaster_write(td, wfd, &request_ver, sizeof(request_ver));
	if (error != 0)
		return (error);
	error = fmaster_read(td, rfd, &ver, sizeof(ver));
	if (error != 0)
		return (error);
	if (ver != 0)
		return (EPROTO);

	fmaster_log(td, LOG_DEBUG, "protocol version for fmhub is %d.", ver);

	return (0);
}

static int
create_data(struct thread *td, int rfd, int wfd, const char *fork_sock,
	    struct fmaster_data **pdata)
{
	struct fmaster_data *data;
	size_t len;
	int error;

	data = fmaster_create_data(td);
	if (data == NULL)
		return (ENOMEM);
	data->rfd = rfd;
	data->wfd = wfd;
	len = sizeof(data->fork_sock);
	error = copystr(fork_sock, data->fork_sock, len, NULL);
	if (error != 0)
		goto fail;
	data->fdata_memory = NULL;
	error = fmaster_initialize_kqueue(td, data);
	if (error != 0)
		goto fail;

	*pdata = data;

	return (0);

fail:
	free(data, M_FMASTER);

	return (error);
}

static int
read_fds(struct thread *td, struct fmaster_data *data)
{
	struct fmaster_vnode *vnode;
	int _, d, error, m, nbytes, pos;

	error = fmaster_read_int32(td, &nbytes, &_);
	if (error != 0)
		return (error);

	fmaster_lock_file_table(td);

	pos = 0;
	while (pos < nbytes) {
		error = fmaster_read_int32(td, &d, &m);
		if (error != 0)
			goto exit;
		vnode = fmaster_alloc_vnode(td);
		if (vnode == NULL) {
			error = ENOMEM;
			goto exit;
		}
		vnode->fv_place = FFP_SLAVE;
		vnode->fv_local = d;
		strcpy(vnode->fv_desc, "default");
		data->fdata_files[d].ff_vnode = vnode;
		pos += m;
	}

	error = 0;
exit:
	fmaster_unlock_file_table(td);

	return (error);
}

/*
 * The function for implementing the syscall.
 */
static int
fmaster_execve(struct thread *td, struct fmaster_execve_args *uap)
{
	struct fmaster_data *data;
	int error, i, rfd, wfd;
	pid_t pid;
	const char *fmt = "%s: pid=%d, rfd=%d, wfd=%d, fork_sock=%s, path=%s\n";
	char fork_sock[MAXPATHLEN], head[32];

	error = copyinstr(uap->fork_sock, fork_sock, sizeof(fork_sock), NULL);
	if (error != 0)
		return (error);
	pid = td->td_proc->p_pid;
	rfd = uap->rfd;
	wfd = uap->wfd;
	snprintf(head, sizeof(head), "fmaster_execve[%d]", pid);
	log(LOG_DEBUG, fmt, head, pid, rfd, wfd, fork_sock, uap->path);
	for (i = 0; uap->argv[i] != NULL; i++)
		log(LOG_DEBUG, "%s: argv[%d]=%s\n", head, i, uap->argv[i]);
	for (i = 0; uap->envp[i] != NULL; i++)
		log(LOG_DEBUG, "%s: envp[%d]=%s\n", head, i, uap->envp[i]);

	error = create_data(td, rfd, wfd, fork_sock, &data);
	if (error != 0)
		return (error);
	td->td_proc->p_emuldata = data;
	error = fmaster_openlog(td);
	if (error != 0)
		return (error);

	if ((error = negotiate_version(td, rfd, wfd)) != 0)
		goto fail;
	error = read_fds(td, data);
	if (error != 0)
		goto fail;

	return (sys_execve(td, (struct execve_args *)(&uap->path)));

fail:
	fmaster_delete_data(data);

	return (error);
}

/*
 * The `sysent' for the new syscall
 */
static struct sysent se = {
	6,				/* sy_narg */
	(sy_call_t *)fmaster_execve	/* sy_call */
};

/*
 * The offset in sysent where the syscall is allocated.
 */
static int offset = NO_SYSCALL;

static eventhandler_tag fmaster_exit_tag;

extern struct sysent fmaster_sysent[];

static void
process_exit(void *_, struct proc *p)
{
	if (p->p_sysent->sv_table != fmaster_sysent)
		return;
	fmaster_delete_data(p->p_emuldata);
}

/*
 * The function called at load/unload.
 */
static int
fmaster_modevent(struct module *_, int cmd, void *__)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD :
		fmaster_exit_tag = EVENTHANDLER_REGISTER(
			process_exit,
			process_exit,
			NULL,
			EVENTHANDLER_PRI_ANY);
		log(LOG_INFO, "loaded fmaster.\n");
		break;
	case MOD_UNLOAD :
		EVENTHANDLER_DEREGISTER(process_exit, fmaster_exit_tag);
		log(LOG_INFO, "unloaded fmaster.\n");
		break;
	default :
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

SYSCALL_MODULE(fmaster, &offset, &se, fmaster_modevent, NULL);

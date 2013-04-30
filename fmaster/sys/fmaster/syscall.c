#include <sys/param.h>
#include <sys/errno.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
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

MALLOC_DEFINE(M_FMASTER, "fmaster", "fmaster");

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

	log(LOG_DEBUG, "Protocol version for fmhub is %d.\n", ver);

	return (0);
}

static struct fmaster_data *
create_data(struct thread *td, int rfd, int wfd)
{
	struct fmaster_data *data;
	int i;

	data = malloc(sizeof(*data), M_FMASTER, M_ZERO | M_NOWAIT);
	if (data == NULL)
		return (NULL);
	data->rfd = rfd;
	data->wfd = wfd;
	for (i = 0; i < FD_NUM; i++)
		data->fds[i] = 0;

	return (data);
}

static int
read_fds(struct thread *td, struct fmaster_data *data)
{
	int _, d, error, m, nbytes, pos;

	error = fmaster_read_int32(td, &nbytes, &_);
	if (error != 0)
		return (error);

	pos = 0;
	while (pos < nbytes) {
		error = fmaster_read_int32(td, &d, &m);
		if (error != 0)
			return (error);
		data->fds[d] = SLAVE_FD2FD(d);
		pos += m;
	}

	return (0);
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
	const char *name = "fmaster_execve";
	const char *fmt = "%s: pid=%d, rfd=%d, wfd=%d, path=%s\n";

	pid = td->td_proc->p_pid;
	log(LOG_DEBUG, fmt, name, pid, uap->rfd, uap->wfd, uap->path);
	for (i = 0; uap->argv[i] != NULL; i++)
		log(LOG_DEBUG, "%s: argv[%d]=%s\n", name, i, uap->argv[i]);
	for (i = 0; uap->envp[i] != NULL; i++)
		log(LOG_DEBUG, "%s: envp[%d]=%s\n", name, i, uap->envp[i]);

	rfd = uap->rfd;
	wfd = uap->wfd;
	if ((error = negotiate_version(td, rfd, wfd)) != 0)
		return (error);

	data = create_data(td, rfd, wfd);
	if (data == NULL)
		return (ENOMEM);
	td->td_proc->p_emuldata = data;
	error = read_fds(td, data);
	if (error != 0) {
		free(data, M_FMASTER);
		return (error);
	}

	return (sys_execve(td, (struct execve_args *)(&uap->path)));
}

/*
 * The `sysent' for the new syscall
 */
static struct sysent se = {
	5,				/* sy_narg */
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
	free(p->p_emuldata, M_FMASTER);
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
		log(LOG_INFO, "Loaded fmaster.\n");
		break;
	case MOD_UNLOAD :
		EVENTHANDLER_DEREGISTER(process_exit, fmaster_exit_tag);
		log(LOG_INFO, "Unnloaded fmaster.\n");
		break;
	default :
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

SYSCALL_MODULE(fmaster, &offset, &se, fmaster_modevent, NULL);

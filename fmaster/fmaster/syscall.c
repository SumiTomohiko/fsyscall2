/*-
 * Copyright (c) 1999 Assar Westerlund
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/share/examples/kld/syscall/module/syscall.c,v 1.6.4.1.2.1 2011/11/11 04:20:22 kensmith Exp $
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/sysent.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>

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
	uint8_t request_ver, ver;

	request_ver = 0;
	fmaster_write_or_die(td, wfd, &request_ver, sizeof(request_ver));
	fmaster_read_or_die(td, rfd, &ver, sizeof(ver));
	if (ver != 0)
		return (EPROTO);

	log(LOG_DEBUG, "Protocol version for fmhub is %d.\n", ver);

	return (0);
}

static struct master_data *
create_data(struct thread *td, int rfd, int wfd)
{
	struct master_data *data;

	data = malloc(sizeof(*data), M_FMASTER, M_ZERO | M_NOWAIT);
	if (data == NULL)
		return (NULL);
	data->rfd = rfd;
	data->wfd = wfd;

	return (data);
}

static void
read_fds(struct thread *td, int fd, struct master_data *data)
{
	int d, m, nbytes, pos;

	nbytes = fmaster_read_int(td, fd);

	pos = 0;
	while (pos < nbytes) {
		d = fmaster_read_int2(td, fd, &m);
		data->fds[d] = SLAVE_FD2FD(d);
		pos += m;
	}
}

/*
 * The function for implementing the syscall.
 */
static int
fmaster_execve(struct thread *td, struct fmaster_execve_args *uap)
{
	struct master_data *data;
	int error, i, rfd, wfd;
	const char *name = "fmaster_execve";
	const char *fmt = "%s: rfd=%d, wfd=%d, path=%s\n";

	log(LOG_DEBUG, fmt, name, uap->rfd, uap->wfd, uap->path);
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
	read_fds(td, rfd, data);

	td->td_proc->p_emuldata = data;

	return (sys_execve(td, (struct execve_args *)(&uap->path)));
}

/*
 * The `sysent' for the new syscall
 */
static struct sysent fmaster_sysent = {
	5,				/* sy_narg */
	(sy_call_t *)fmaster_execve	/* sy_call */
};

/*
 * The offset in sysent where the syscall is allocated.
 */
static int offset = NO_SYSCALL;

#if 0
static eventhandler_tag fmaster_exit_tag;

extern struct sysentvec elf32_freebsd_sysvec;

static void
process_exit(void *_, struct proc *p)
{
	if (p->p_sysent != &elf32_freebsd_sysvec)
		return;
	free(p->p_emuldata, M_FMASTER);
}
#endif

/*
 * The function called at load/unload.
 */
static int
fmaster_modevent(struct module *_, int cmd, void *__)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD :
		printf("fmaster loaded.\n");
#if 0
		fmaster_exit_tag = EVENTHANDLER_REGISTER(process_exit, process_exit, NULL, EVENTHANDLER_PRI_ANY);
#endif
		break;
	case MOD_UNLOAD :
		printf("fmaster unloaded.\n");
#if 0
		EVENTHANDLER_DEREGISTER(process_exit, fmaster_exit_tag);
#endif
		break;
	default :
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

SYSCALL_MODULE(fmaster, &offset, &fmaster_sysent, fmaster_modevent, NULL);

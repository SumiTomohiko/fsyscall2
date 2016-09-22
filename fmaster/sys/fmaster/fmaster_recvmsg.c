#include <sys/param.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static const char *sysname = "recvmsg";

/*******************************************************************************
 * code for master
 */

static int
recvmsg_master(struct thread *td, int lfd, struct msghdr *msg, int flags)
{
	struct recvmsg_args args;

	/* TODO: detect executing for slave */

	args.s = lfd;
	args.msg = msg;
	args.flags = flags;

	return (sys_recvmsg(td, &args));
}

/*******************************************************************************
 * code for slave
 */

static int
execute_call(struct thread *td, int lfd, const struct msghdr *kmsg, int flags)
{
	struct payload *payload;
	struct iovec *iov;
	int error, i, iovlen;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);
	error = fsyscall_payload_add_int(payload, lfd);
	if (error != 0)
		goto exit;
	if (kmsg->msg_name != NULL) {
		error = ENOTSUP;
		goto exit;
	}
	error = fsyscall_payload_add_int(payload, MSGHDR_MSG_NAME_NULL);
	if (error != 0)
		goto exit;
	iovlen = kmsg->msg_iovlen;
	error = fsyscall_payload_add_int(payload, iovlen);
	if (error != 0)
		goto exit;
	iov = kmsg->msg_iov;
	for (i = 0; i < iovlen; i++) {
		error = fsyscall_payload_add_int(payload, iov[i].iov_len);
		if (error != 0)
			goto exit;
	}
	/*
	 * msg_controllen depends on architecture. So I do not need to send it.
	 * But if this does not exist, the slave can not know what the master
	 * wants. I expect that this information works as a hint.
	 */
	fmaster_log(td, LOG_DEBUG,
		    "%s: kmsg->msg_controllen=%ld",
		    sysname, kmsg->msg_controllen);
	error = fsyscall_payload_add_socklen(payload, kmsg->msg_controllen);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_int(payload, kmsg->msg_flags);
	if (error != 0)
		goto exit;

	error = fsyscall_payload_add_int(payload, flags);
	if (error != 0)
		goto exit;

	error = fmaster_write_payloaded_command(td, RECVMSG_CALL, payload);
	if (error != 0)
		goto exit;

	error = 0;
exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

struct cmsgspec {
	int		cmsgspec_level;
	int 		cmsgspec_type;
	socklen_t	cmsgspec_len;
	socklen_t	cmsgspec_space;
	int		cmsgspec_nfds;		/* for SCM_RIGHTS */
};

static int
read_cmsgspecs(struct thread *td, int ncmsghdrs, struct cmsgspec **cmsgspecs,
	       payload_size_t *payload_size)
{
	struct cmsgspec *spec, *specs;
	payload_size_t actual_payload_size, level_len, nfds_len, type_len;
	size_t datasize, size;
	int error, i, level, nfds, type;

	size = sizeof(specs[0]) * ncmsghdrs;
	specs = (struct cmsgspec *)fmaster_malloc(td, size);
	if (specs == NULL)
		return (ENOMEM);

	actual_payload_size = 0;
	for (i = 0; i < ncmsghdrs; i++) {
		spec = &specs[i];

		error = fmaster_read_int(td, &level, &level_len);
		if (error != 0)
			return (error);
		actual_payload_size += level_len;
		error = fmaster_read_int(td, &type, &type_len);
		if (error != 0)
			return (error);
		actual_payload_size += type_len;
		spec->cmsgspec_level = level;
		spec->cmsgspec_type = type;

		switch (level) {
		case SOL_SOCKET:
			switch (type) {
			case SCM_CREDS:
				datasize = sizeof(struct cmsgcred);
				break;
			case SCM_RIGHTS:
				error = fmaster_read_int(td, &nfds, &nfds_len);
				if (error != 0)
					return (error);
				actual_payload_size += nfds_len;
				spec->cmsgspec_nfds = nfds;
				datasize = sizeof(int) * nfds;
				break;
			default:
				datasize = 0;
				break;
			}
			break;
		default:
			datasize = 0;
			break;
		}

		spec->cmsgspec_len = CMSG_LEN(datasize);
		spec->cmsgspec_space = CMSG_SPACE(datasize);
	}

	*cmsgspecs = specs;
	*payload_size = actual_payload_size;

	return (0);
}

static socklen_t
compute_space(int ncmsghdrs, const struct cmsgspec *cmsgspecs)
{
	socklen_t n;
	int i;

	n = 0;
	for (i = 0; i < ncmsghdrs; i++)
		n += cmsgspecs[i].cmsgspec_space;

	return (n);
}

static int
read_passed_fds(struct thread *td, struct cmsgspec *cmsgspec, void *cmsgdata,
		payload_size_t *actual_payload_size)
{
	payload_size_t lfd_len, payload_size;
	int error, i, lfd, nfds, *pfd;
	const char *fmt = "passed via SCM_RIGHTS (local: %d)";
	char desc[256];

	nfds = cmsgspec->cmsgspec_nfds;

	payload_size = 0;
	for (i = 0, pfd = (int *)cmsgdata; i < nfds; i++, pfd++) {
		error = fmaster_read_int(td, &lfd, &lfd_len);
		if (error != 0)
			return (error);
		payload_size += lfd_len;

		snprintf(desc, sizeof(desc), fmt, lfd);
		/*
		 * TODO: Which type is best in this case?
		 */
		error = fmaster_register_file(td, DTYPE_VNODE, FFP_SLAVE, lfd,
					      pfd, desc);
		if (error != 0)
			return (error);
	}

	*actual_payload_size = payload_size;

	return (0);
}

static int
read_cmsgcred(struct thread *td, char *cmsgdata, payload_size_t *payload_size)
{
	struct cmsgcred *cred;
	payload_size_t actual_payload_size, euid_len, gid_len, group_len;
	payload_size_t ngroups_len, pid_len, uid_len;
	gid_t *group;
	int error;
	short i, ngroups;

	cred = (struct cmsgcred *)cmsgdata;
	actual_payload_size = 0;

	error = fmaster_read_pid(td, &cred->cmcred_pid, &pid_len);
	if (error != 0)
		return (error);
	actual_payload_size += pid_len;

	error = fmaster_read_uid(td, &cred->cmcred_uid, &uid_len);
	if (error != 0)
		return (error);
	actual_payload_size += uid_len;

	error = fmaster_read_uid(td, &cred->cmcred_euid, &euid_len);
	if (error != 0)
		return (error);
	actual_payload_size += euid_len;

	error = fmaster_read_gid(td, &cred->cmcred_gid, &gid_len);
	if (error != 0)
		return (error);
	actual_payload_size += gid_len;

	error = fmaster_read_short(td, &ngroups, &ngroups_len);
	if (error != 0)
		return (error);
	cred->cmcred_ngroups = ngroups;
	actual_payload_size += ngroups_len;

	for (i = 0; i < ngroups; i++) {
		group = &cred->cmcred_groups[i];
		error = fmaster_read_gid(td, group, &group_len);
		if (error != 0)
			return (error);
		actual_payload_size += group_len;
	}

	*payload_size = actual_payload_size;

	return (0);
}

static int
copyout_controllen(struct msghdr *msg, socklen_t controllen)
{
	int error;

	error = copyout(&controllen, &msg->msg_controllen, sizeof(controllen));
	if (error != 0)
		return (error);

	return (0);
}

static int
execute_return(struct thread *td, struct msghdr *umsg, struct msghdr *kmsg)
{
	struct cmsghdr *cmsghdr, *kcontrol, *ucontrol;
	struct cmsgspec *cmsgspec, *cmsgspecs;
	struct iovec *iov, *piov;
	payload_size_t actual_payload_size, cmsgdata_len, cmsgspecs_len;
	payload_size_t errnum_len, ncmsghdrs_len, payload_size, retval_len;
	size_t len;
	ssize_t rest, retval;
	socklen_t controllen, space;
	command_t cmd;
	int errnum, error, i, level, ncmsghdrs, type;
	char *buf, *cmsgdata, *p;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != RECVMSG_RETURN) {
		fmaster_log(td, LOG_ERR, "command mismatched: actual=%d", cmd);
		return (EPROTO);
	}
	error = fmaster_read_payload_size(td, &payload_size);
	if (error != 0)
		return (error);

	error = fmaster_read_ssize(td, &retval, &retval_len);
	if (error != 0)
		return (error);

	actual_payload_size = retval_len;
	if (retval == -1) {
		error = fmaster_read_int(td, &errnum, &errnum_len);
		if (error != 0)
			return (error);
		actual_payload_size += errnum_len;
		if (payload_size != actual_payload_size) {
			fmaster_log(td, LOG_ERR,
				    "payload size mismatched for error: expecte"
				    "d=%zu, actual=%zu",
				    payload_size, actual_payload_size);
			return (EPROTO);
		}

		return (errnum);
	}

	buf = (char *)fmaster_malloc(td, retval);
	if (buf == NULL)
		return (ENOMEM);
	error = fmaster_read(td, fmaster_rfd_of_thread(td), buf, retval);
	if (error != 0)
		return (error);
	actual_payload_size += retval;
	iov = kmsg->msg_iov;
	for (rest = retval, i = 0; 0 < rest; rest -= len, i++) {
		piov = &iov[i];
		len = MIN(rest, piov->iov_len);
		error = copyout(buf + retval - rest, piov->iov_base, len);
		if (error != 0)
			return (error);
	}

	ucontrol = kmsg->msg_control;
	if (ucontrol != NULL) {
		error = fmaster_read_int(td, &ncmsghdrs, &ncmsghdrs_len);
		if (error != 0)
			return (error);
		actual_payload_size += ncmsghdrs_len;
		fmaster_log(td, LOG_DEBUG,
			    "%s: ncmsghdrs=%d",
			    sysname, ncmsghdrs);

		error = read_cmsgspecs(td, ncmsghdrs, &cmsgspecs,
				       &cmsgspecs_len);
		if (error != 0)
			return (error);
		actual_payload_size += cmsgspecs_len;

		space = compute_space(ncmsghdrs, cmsgspecs);
		fmaster_log(td, LOG_DEBUG, "%s: space=%d", sysname, space);
		kcontrol = (struct cmsghdr *)fmaster_malloc(td, space);
		if (kcontrol == NULL)
			return (ENOMEM);

		/*
		 * The following assignment is not needed for executing. It is
		 * only for logging.
		 */
		kmsg->msg_control = kcontrol;

		p = (char *)kcontrol;
		for (i = 0; i < ncmsghdrs; i++) {
			cmsgspec = &cmsgspecs[i];
			level = cmsgspec->cmsgspec_level;
			type = cmsgspec->cmsgspec_type;

			cmsghdr = (struct cmsghdr *)p;
			cmsghdr->cmsg_len = cmsgspec->cmsgspec_len;
			cmsghdr->cmsg_level = level;
			cmsghdr->cmsg_type = type;

			cmsgdata = CMSG_DATA(cmsghdr);
			switch (level) {
			case SOL_SOCKET:
				switch (type) {
				case SCM_CREDS:
					error = read_cmsgcred(td, cmsgdata,
							      &cmsgdata_len);
					break;
				case SCM_RIGHTS:
					error = read_passed_fds(td, cmsgspec,
								cmsgdata,
								&cmsgdata_len);
					break;
				default:
					fmaster_log(td, LOG_ERR,
						    "unsupported type: %d",
						    type);
					return (EPROTO);
				}
				break;
			default:
				fmaster_log(td, LOG_ERR,
					    "unsupported level: %d", level);
				return (EPROTO);
			}
			if (error != 0)
				return (error);
			actual_payload_size += cmsgdata_len;

			p += cmsgspec->cmsgspec_space;
		}

		if (space <= kmsg->msg_controllen) {
			error = copyout(kcontrol, ucontrol, space);
			if (error != 0)
				return (error);
			controllen = space;
		}
		else
			controllen = 0;
		/* This assignment is only for logging */
		kmsg->msg_controllen = space;

		error = copyout_controllen(umsg, controllen);
		if (error != 0)
			return (error);
	}

	if (actual_payload_size != payload_size) {
		fmaster_log(td, LOG_ERR,
			    "payload size mismatched: expected=%zu, actual=%zu",
			    payload_size, actual_payload_size);
		return (EPROTO);
	}

	td->td_retval[0] = retval;

	return (0);
}

static int
recvmsg_slave(struct thread *td, struct msghdr *umsg, int lfd,
	      struct msghdr *kmsg, int flags)
{
	int error;

	error = execute_call(td, lfd, kmsg, flags);
	if (error != 0)
		return (error);
	error = execute_return(td, umsg, kmsg);
	if (error != 0)
		goto exit;

	error = 0;
exit:
	fmaster_freeall(td);

	return (error);
}

/*******************************************************************************
 * shared code
 */

static int
fmaster_recvmsg_main(struct thread *td, struct fmaster_recvmsg_args *uap)
{
	struct msghdr kmsg, *umsg;
	enum fmaster_file_place place;
	int error, lfd;

	umsg = uap->msg;
	error = fmaster_copyin_msghdr(td, umsg, &kmsg);
	if (error != 0)
		return (error);

	error = fmaster_get_vnode_info(td, uap->s, &place, &lfd);
	if (error != 0)
		goto exit;
	switch (place) {
	case FFP_MASTER:
		error = recvmsg_master(td, lfd, umsg, uap->flags);
		if (error != 0)
			goto exit;
		break;
	case FFP_SLAVE:
		error = recvmsg_slave(td, umsg, lfd, &kmsg, uap->flags);
		if (error != 0)
			goto exit;
		break;
	case FFP_PENDING_SOCKET:
		error = ENOTCONN;
		goto exit;
	default:
		error = EINVAL;
		goto exit;
	}

	error = fmaster_log_msghdr(td, sysname, &kmsg, td->td_retval[0]);
	if (error != 0)
		goto exit;

exit:
	free(kmsg.msg_iov, M_IOV);
	free(kmsg.msg_name, M_TEMP);

	return (error);
}

int
sys_fmaster_recvmsg(struct thread *td, struct fmaster_recvmsg_args *uap)
{
	struct flag_definition defs[] = {
		DEFINE_FLAG(MSG_OOB),
		DEFINE_FLAG(MSG_PEEK),
		DEFINE_FLAG(MSG_WAITALL),
		DEFINE_FLAG(MSG_DONTWAIT),
		DEFINE_FLAG(MSG_CMSG_CLOEXEC)
	};
	struct timeval time_start;
	int error, flags;
	char flagsstr[256];

	flags = uap->flags;
	fmaster_chain_flags(flagsstr, sizeof(flagsstr), flags, defs,
			    array_sizeof(defs));
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: s=%d, msg=%p, flags=0x%x (%s)",
		    sysname, uap->s, uap->msg, flags, flagsstr);
	microtime(&time_start);

	error = fmaster_recvmsg_main(td, uap);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

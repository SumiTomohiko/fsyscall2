#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

/*******************************************************************************
 * code for master
 */

/* nothing */

/*******************************************************************************
 * code for slave
 */

static int
execute_call(struct thread *td, int lfd, const struct msghdr *kmsg, int flags)
{
	struct cmsghdr *cmsghdr;
	struct payload *payload;
	struct iovec *iov;
	socklen_t controllen;
	int error, i, iovlen, level, type;
	void *control;

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
	control = kmsg->msg_control;
	if (control == NULL) {
		error = fsyscall_payload_add_int(payload,
						 MSGHDR_MSG_CONTROL_NULL);
		if (error != 0)
			goto exit;
	}
	else {
		error = fsyscall_payload_add_int(payload,
						 MSGHDR_MSG_CONTROL_NOT_NULL);
		if (error != 0)
			goto exit;
		controllen = kmsg->msg_controllen;
		if (controllen < sizeof(struct cmsghdr)) {
			error = EINVAL;
			goto exit;
		}
		cmsghdr = (struct cmsghdr *)control;
		level = cmsghdr->cmsg_level;
		type = cmsghdr->cmsg_type;
		if ((level != SOL_SOCKET) || (type != SCM_CREDS)) {
			error = ENOTSUP;
			goto exit;
		}
		error = fsyscall_payload_add_int(payload, level);
		if (error != 0)
			goto exit;
		error = fsyscall_payload_add_int(payload, type);
		if (error != 0)
			goto exit;
	}

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

static int
execute_return(struct thread *td, struct msghdr *umsg,
	       const struct msghdr *kmsg)
{
	struct msghdr msg;
	struct cmsghdr *control;
	struct cmsgcred *cred;
	struct malloc_type *mt;
	struct iovec *iov, *piov;
	payload_size_t actual_payload_size, errnum_len, euid_len, gid_len;
	payload_size_t group_len, ngroups_len, payload_size, pid_len;
	payload_size_t retval_len, uid_len;
	size_t len;
	ssize_t rest, retval;
	command_t cmd;
	gid_t *group;
	int errnum, error, i;
	short ngroups;
	char *buf;

	error = fmaster_read_command(td, &cmd);
	if (error != 0)
		return (error);
	if (cmd != RECVMSG_RETURN)
		return (EPROTO);
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
		if (payload_size != actual_payload_size)
			return (EPROTO);

		return (errnum);
	}

	mt = M_TEMP;
	buf = (char *)malloc(retval, mt, M_WAITOK);
	if (buf == NULL)
		return (ENOMEM);
	error = fmaster_read(td, fmaster_rfd_of_thread(td), buf, retval);
	if (error != 0)
		goto finally;
	iov = kmsg->msg_iov;
	for (rest = retval, i = 0; 0 < rest; rest -= len, i++) {
		piov = &iov[i];
		len = MIN(rest, piov->iov_len);
		error = copyout(buf + retval - rest, piov->iov_base, len);
		if (error != 0)
			goto finally;
	}
finally:
	free(buf, mt);
	if (error != 0)
		return (error);
	actual_payload_size += retval;

	control = kmsg->msg_control;
	if (control != NULL) {
		switch (control->cmsg_level) {
		case SOL_SOCKET:
			switch (control->cmsg_type) {
			case SCM_CREDS:
				cred = (struct cmsgcred *)CMSG_DATA(control);

				error = fmaster_read_pid(td, &cred->cmcred_pid,
							 &pid_len);
				if (error != 0)
					return (error);
				actual_payload_size += pid_len;

				error = fmaster_read_uid(td, &cred->cmcred_uid,
							 &uid_len);
				if (error != 0)
					return (error);
				actual_payload_size += uid_len;

				error = fmaster_read_uid(td, &cred->cmcred_euid,
							 &euid_len);
				if (error != 0)
					return (error);
				actual_payload_size += euid_len;

				error = fmaster_read_gid(td, &cred->cmcred_gid,
							 &gid_len);
				if (error != 0)
					return (error);
				actual_payload_size += gid_len;

				error = fmaster_read_short(td, &ngroups,
							   &ngroups_len);
				if (error != 0)
					return (error);
				cred->cmcred_ngroups = ngroups;
				actual_payload_size += ngroups_len;

				for (i = 0; i < ngroups; i++) {
					group = &cred->cmcred_groups[i];
					error = fmaster_read_gid(td, group,
								 &group_len);
					if (error != 0)
						return (error);
					actual_payload_size += group_len;
				}
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
		error = copyin(umsg, &msg, sizeof(msg));
		if (error != 0)
			return (error);
		error = copyout(control, msg.msg_control, kmsg->msg_controllen);
		if (error != 0)
			return (error);
	}

	if (actual_payload_size != payload_size)
		return (EPROTO);

	td->td_retval[0] = retval;

	return (0);
}

static int
recvmsg_slave(struct thread *td, struct msghdr *umsg, int lfd,
	      const struct msghdr *kmsg, int flags)
{
	int error;

	error = execute_call(td, lfd, kmsg, flags);
	if (error != 0)
		return (error);
	error = execute_return(td, umsg, kmsg);
	if (error != 0)
		return (error);

	return (0);
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
		error = ENOSYS;
		break;
	case FFP_SLAVE:
		error = recvmsg_slave(td, umsg, lfd, &kmsg, uap->flags);
		break;
	default:
		error = EINVAL;
		break;
	}

exit:
	free(kmsg.msg_control, M_TEMP);
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
		DEFINE_FLAG(MSG_DONTWAIT)
	};
	struct timeval time_start;
	int error, flags;
	const char *sysname = "recvmsg";
	char flagsstr[64];

	flags = uap->flags;
	fmaster_chain_flags(flagsstr, sizeof(flagsstr), flags, defs,
			    array_sizeof(defs));
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: s=%d, msg=%p, flags=%d (%s)",
		    sysname, uap->s, uap->msg, flags, flagsstr);
	microtime(&time_start);

	error = fmaster_recvmsg_main(td, uap);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

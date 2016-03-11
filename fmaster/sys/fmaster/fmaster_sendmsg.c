#include <sys/param.h>
#include <sys/limits.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static const char *sysname = "sendmsg";

/*******************************************************************************
 * code for master
 */

static bool
detect_unsupported_control(struct msghdr *msg)
{
	struct cmsghdr *cmsghdr;

	for (cmsghdr = CMSG_FIRSTHDR(msg);
	     cmsghdr != NULL;
	     cmsghdr = CMSG_NXTHDR(msg, cmsghdr)) {
		switch (cmsghdr->cmsg_level) {
		case SOL_SOCKET:
			switch (cmsghdr->cmsg_type) {
			case SCM_CREDS:
				break;
			case SCM_RIGHTS:
			default:
				return (true);
			}
			break;
		default:
			return (true);
		}
	}

	return (false);
}

static int
sendmsg_master(struct thread *td, struct msghdr *kmsg, int lfd,
	       struct msghdr *umsg, int flags)
{
	struct sendmsg_args args;

	if (detect_unsupported_control(kmsg))
		return (EOPNOTSUPP);

	args.s = lfd;
	args.msg = umsg;
	args.flags = flags;

	return (sys_sendmsg(td, &args));
}

/*******************************************************************************
 * code for slave
 */

static int
count_cmsghdr(struct msghdr *msg)
{
	struct cmsghdr *cmsghdr;
	int n;

	n = 0;
	for (cmsghdr = CMSG_FIRSTHDR(msg);
	     cmsghdr != NULL;
	     cmsghdr = CMSG_NXTHDR(msg, cmsghdr))
		n++;

	return (n);
}

#define	ASSERT_SCM_RIGHTS(cmsghdr)	do {			\
	KASSERT((cmsghdr)->cmsg_level == SOL_SOCKET,		\
		("cmsg_level must be SOL_SOCKET, but %d",	\
		 (cmsghdr)->cmsg_level));			\
	KASSERT((cmsghdr)->cmsg_type = SCM_RIGHTS,		\
		("cmsg_type must be SCM_RIGHTS, but %d",	\
		 (cmsghdr)->cmsg_type));			\
} while (0)

static int
compute_nfds_to_pass(struct cmsghdr *cmsghdr)
{
	char *data, *pend;

	ASSERT_SCM_RIGHTS(cmsghdr);

	data = (char *)CMSG_DATA(cmsghdr);
	pend = (char *)cmsghdr + cmsghdr->cmsg_len;

	return (((uintptr_t)pend - (uintptr_t)data) / sizeof(int));
}

static int
add_control_size_info_to_payload(struct thread *td, struct payload *payload,
				 struct msghdr *msg)
{
	struct cmsghdr *cmsghdr;
	int error, level, nfds, type;

	for (cmsghdr = CMSG_FIRSTHDR(msg);
	     cmsghdr != NULL;
	     cmsghdr = CMSG_NXTHDR(msg, cmsghdr)) {
		level = cmsghdr->cmsg_level;
		type = cmsghdr->cmsg_type;
		error = fsyscall_payload_add_int(payload, level);
		if (error != 0)
			return (error);
		error = fsyscall_payload_add_int(payload, type);
		if (error != 0)
			return (error);
		switch (level) {
		case SOL_SOCKET:
			switch (type) {
			case SCM_CREDS:
				/* nothing */
				break;
			case SCM_RIGHTS:
				nfds = compute_nfds_to_pass(cmsghdr);
				error = fsyscall_payload_add_int(payload, nfds);
				if (error != 0)
					return (error);
				break;
			default:
				return (EOPNOTSUPP);
			}
			break;
		default:
			return (EOPNOTSUPP);
		}
	}

	return (0);
}

static int
add_fds_to_payload(struct thread *td, struct payload *payload,
		   struct cmsghdr *cmsghdr)
{
	enum fmaster_file_place place;
	int error, lfd, *p, *pend;

	ASSERT_SCM_RIGHTS(cmsghdr);

	pend = (int *)((char *)cmsghdr + cmsghdr->cmsg_len);
	for (p = (int *)CMSG_DATA(cmsghdr); p < pend; p++) {
		error = fmaster_get_vnode_info(td, *p, &place, &lfd);
		if (error != 0)
			return (error);
		if (place != FFP_SLAVE)
			return (EBADF);

		error = fsyscall_payload_add_int(payload, lfd);
		if (error != 0)
			return (error);
	}

	return (0);
}

static int
execute_call(struct thread *td, int lfd, struct msghdr *msg, int flags)
{
	struct payload *payload;
	struct cmsghdr *cmsghdr;
	struct iovec *iov;
	size_t len;
	int error, i, iovlen, ncmsghdr;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);

	error = fsyscall_payload_add_int(payload, lfd);
	if (error != 0)
		goto exit;

	/*
	 * I do not send namelen. Because it depends on architecture. All I do
	 * here is sending logical structure. The slave can compute length from
	 * the given data.
	 */
	if (msg->msg_name != NULL) {
		fmaster_log(td, LOG_DEBUG, "msg->msg_name != NULL");
		error = ENOTSUP;
		goto exit;
	}
	error = fsyscall_payload_add_int(payload, MSGHDR_MSG_NAME_NULL);
	if (error != 0)
		goto exit;

	iovlen = msg->msg_iovlen;
	error = fsyscall_payload_add_int(payload, iovlen);
	if (error != 0)
		goto exit;
	for (i = 0; i < iovlen; i++) {
		iov = &msg->msg_iov[i];
		len = iov->iov_len;
		error = fsyscall_payload_add_int(payload, len);
		if (error != 0)
			goto exit;
		error = fsyscall_payload_add(payload, iov->iov_base, len);
		if (error != 0)
			goto exit;
	}

	/*
	 * I also do not send msg_controllen. It depends on machine
	 * architecture. The slave can compute it.
	 */
	if (msg->msg_control == NULL) {
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
		ncmsghdr = count_cmsghdr(msg);
		error = fsyscall_payload_add_int(payload, ncmsghdr);
		if (error != 0)
			goto exit;

		/* sends level and type for the peer to decide buffer size */
		error = add_control_size_info_to_payload(td, payload, msg);
		if (error != 0)
			goto exit;

		for (cmsghdr = CMSG_FIRSTHDR(msg);
		     cmsghdr != NULL;
		     cmsghdr = CMSG_NXTHDR(msg, cmsghdr)) {
			switch (cmsghdr->cmsg_level) {
			case SOL_SOCKET:
				switch (cmsghdr->cmsg_type) {
				case SCM_CREDS:
					/* nothing */
					break;
				case SCM_RIGHTS:
					error = add_fds_to_payload(td, payload,
								   cmsghdr);
					if (error != 0)
						goto exit;
					break;
				default:
					error = ENOTSUP;
					goto exit;
				}
				break;
			default:
				error = ENOTSUP;
				goto exit;
			}
		}
	}

	error = fsyscall_payload_add_int(payload, msg->msg_flags);
	if (error != 0)
		goto exit;

	error = fsyscall_payload_add_int(payload, flags);
	if (error != 0)
		goto exit;

	error = fmaster_write_payloaded_command(td, SENDMSG_CALL, payload);
	if (error != 0)
		goto exit;

	error = 0;
exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

static int
sendmsg_slave(struct thread *td, struct msghdr *umsg, int lfd,
	      struct msghdr *kmsg, int flags)
{
	int error;

	error = execute_call(td, lfd, kmsg, flags);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_generic64(td, SENDMSG_RETURN);
	if (error != 0)
		return (error);

	return (0);
}

/*******************************************************************************
 * shared code
 */

static int
copyin_iov_contents(struct thread *td, struct iovec *iov, int iovlen,
		    struct malloc_type *mt)
{
	struct iovec *piov;
	int error, i, len;
	void **p, *q;

	mt = M_TEMP;
	p = malloc(sizeof(*p) * iovlen, mt, M_WAITOK);
	if (p == NULL)
		return (ENOMEM);
	for (i = 0; i < iovlen; i++)
		p[i] = NULL;
	for (i = 0; i < iovlen; i++) {
		piov = &iov[i];
		len = piov->iov_len;
		q = malloc(len, mt, M_WAITOK);
		if (q == NULL) {
			error = ENOMEM;
			goto fail;
		}
		error = copyin(piov->iov_base, q, len);
		if (error != 0)
			goto fail;
		p[i] = q;
	}
	for (i = 0; i < iovlen; i++)
		iov[i].iov_base = p[i];

	free(p, mt);

	return (0);

fail:
	for (i = 0; i < iovlen; i++)
		free(p[i], mt);
	free(p, mt);

	return (error);
}

static int
copyin_control(struct thread *td, struct msghdr *msg, struct malloc_type *mt)
{
	socklen_t controllen;
	int error;
	void *control;

	if (msg->msg_control == NULL)
		return (0);

	controllen = msg->msg_controllen;
	control = malloc(controllen, mt, M_WAITOK);
	if (control == NULL)
		return (ENOMEM);
	error = copyin(msg->msg_control, control, controllen);
	if (error != 0)
		goto fail;
	msg->msg_control = control;

	return (0);

fail:
	free(control, mt);
	return (error);
}

static int
fmaster_sendmsg_main(struct thread *td, struct fmaster_sendmsg_args *uap)
{
	struct malloc_type *mt;
	struct msghdr kmsg, *umsg;
	enum fmaster_file_place place;
	int error, i, iovlen, lfd;

	mt = M_TEMP;

	umsg = uap->msg;
	error = fmaster_copyin_msghdr(td, umsg, &kmsg);
	if (error != 0)
		return (error);
	iovlen = kmsg.msg_iovlen;
	error = copyin_iov_contents(td, kmsg.msg_iov, iovlen, mt);
	if (error != 0)
		goto exit1;
	error = copyin_control(td, &kmsg, mt);
	if (error != 0)
		goto exit1;

	error = fmaster_log_msghdr(td, sysname, &kmsg, SIZE_MAX);
	if (error != 0)
		goto exit2;

	error = fmaster_get_vnode_info(td, uap->s, &place, &lfd);
	if (error != 0)
		goto exit2;
	switch (place) {
	case FFP_MASTER:
		error = sendmsg_master(td, &kmsg, lfd, umsg, uap->flags);
		break;
	case FFP_SLAVE:
		error = sendmsg_slave(td, umsg, lfd, &kmsg, uap->flags);
		break;
	case FFP_PENDING_SOCKET:
		error = ENOTCONN;
		break;
	default:
		error = EBADF;
		break;
	}

exit2:
	for (i = 0; i < iovlen; i++)
		free(kmsg.msg_iov[i].iov_base, mt);
exit1:
	free(kmsg.msg_control, mt);
	free(kmsg.msg_iov, M_IOV);
	free(kmsg.msg_name, M_TEMP);

	return (error);
}

int
sys_fmaster_sendmsg(struct thread *td, struct fmaster_sendmsg_args *uap)
{
	struct flag_definition defs[] = {
		DEFINE_FLAG(MSG_OOB),
		DEFINE_FLAG(MSG_DONTROUTE),
		DEFINE_FLAG(MSG_EOR),
		DEFINE_FLAG(MSG_EOF),
		DEFINE_FLAG(MSG_NOSIGNAL)
	};
	struct timeval time_start;
	int error, flags;
	char flagsstr[64];

	flags = uap->flags;
	fmaster_chain_flags(flagsstr, sizeof(flagsstr), flags, defs,
			    array_sizeof(defs));
	fmaster_log(td, LOG_DEBUG,
		    "%s: started: s=%d, msg=%p, flags=%d (%s)",
		    sysname, uap->s, uap->msg, flags, flagsstr);
	microtime(&time_start);

	error = fmaster_sendmsg_main(td, uap);

	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

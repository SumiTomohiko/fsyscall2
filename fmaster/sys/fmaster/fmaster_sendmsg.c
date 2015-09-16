#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/uio.h>

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
execute_call(struct thread *td, int lfd, const struct msghdr *msg, int flags)
{
	struct payload *payload;
	struct cmsghdr *cmsghdr;
	struct iovec *iov;
	size_t len;
	socklen_t controllen;
	int error, i, iovlen, level, type;
	void  *control;

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
	 * I also do not send controllen. It depends on machine architecture.
	 * The slave can compute it.
	 */
	control = msg->msg_control;
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
		controllen = msg->msg_controllen;
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
	      const struct msghdr *kmsg, int flags)
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

static const char *sysname = "sendmsg";

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

static int
log_msg(struct thread *td, const struct msghdr *msg)
{
	struct iovec *iov, *p;
	int controllen, i, iovlen, namelen;
	char buf[256];

#define	LOG(fmt, ...)	do {						\
	fmaster_log(td, LOG_DEBUG, "%s: " fmt, sysname, __VA_ARGS__);	\
} while (0)
#define	DUMP(p, len)	dump(buf, sizeof(buf), (p), (len))
	namelen = msg->msg_namelen;
	LOG("msg->msg_name=%s", DUMP(msg->msg_name, namelen));
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
	controllen = msg->msg_controllen;
	LOG("msg->msg_control=%s", DUMP(msg->msg_control, controllen));
	LOG("msg->msg_controllen=%d", controllen);
	LOG("msg->msg_flags=%d", msg->msg_flags);
#undef	DUMP
#undef	LOG

	return (0);
}

static int
copyin_iov_contents(struct thread *td, struct iovec *iov, int iovlen)
{
	struct iovec *piov;
	int error, i, len;
	void **p, *q;

	p = malloc(sizeof(*p) * iovlen, M_TEMP, M_WAITOK);
	if (p == NULL)
		return (ENOMEM);
	for (i = 0; i < iovlen; i++)
		p[i] = NULL;
	for (i = 0; i < iovlen; i++) {
		piov = &iov[i];
		len = piov->iov_len;
		q = malloc(len, M_TEMP, M_WAITOK);
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

	free(p, M_TEMP);

	return (0);

fail:
	for (i = 0; i < iovlen; i++)
		free(p[i], M_TEMP);
	free(p, M_TEMP);

	return (error);
}

static int
fmaster_sendmsg_main(struct thread *td, struct fmaster_sendmsg_args *uap)
{
	struct msghdr kmsg, *umsg;
	enum fmaster_file_place place;
	int error, i, iovlen, lfd;

	umsg = uap->msg;
	error = fmaster_copyin_msghdr(td, umsg, &kmsg);
	if (error != 0)
		return (error);
	iovlen = kmsg.msg_iovlen;
	error = copyin_iov_contents(td, kmsg.msg_iov, iovlen);
	if (error)
		goto exit1;

	error = log_msg(td, &kmsg);
	if (error != 0)
		goto exit2;

	error = fmaster_get_vnode_info(td, uap->s, &place, &lfd);
	if (error != 0)
		goto exit2;
	switch (place) {
	case FFP_MASTER:
		error = ENOSYS;
		break;
	case FFP_SLAVE:
		error = sendmsg_slave(td, umsg, lfd, &kmsg, uap->flags);
		break;
	default:
		error = EBADF;
		break;
	}

exit2:
	for (i = 0; i < iovlen; i++)
		free(kmsg.msg_iov[i].iov_base, M_TEMP);
exit1:
	free(kmsg.msg_control, M_TEMP);
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

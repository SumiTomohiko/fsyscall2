#include <sys/param.h>
#include <sys/proc.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/uio.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

#if 0
/*******************************************************************************
 * code for slave
 */

static int
sendmsg_slave(struct thread *td, int lfd, const struct msghdr *msg, int flags)
{

	return (ENOSYS);
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
	struct msghdr msg;
	struct iovec *iov;
	unsigned long namelen;
	enum fmaster_file_place place;
	int controllen, error, i, iovlen, lfd;
	void *control, *name;

	error = copyin(uap->msg, &msg, sizeof(msg));
	if (error != 0)
		return (error);
	namelen = msg.msg_namelen;
	name = malloc(namelen, M_TEMP, M_WAITOK);
	if (name == NULL)
		return (ENOMEM);
	error = copyin(msg.msg_name, name, namelen);
	if (error != 0)
		goto exit1;
	msg.msg_name = name;
	iovlen = msg.msg_iovlen;
	error = copyiniov(msg.msg_iov, iovlen, &iov, EMSGSIZE);
	if (error != 0)
		goto exit1;
	error = copyin_iov_contents(td, iov, iovlen);
	if (error)
		goto exit2;
	msg.msg_iov = iov;
	controllen = msg.msg_controllen;
	control = malloc(controllen, M_TEMP, M_WAITOK);
	if (control == NULL) {
		error = ENOMEM;
		goto exit3;
	}
	error = copyin(msg.msg_control, control, controllen);
	if (error != 0)
		goto exit4;
	msg.msg_control = control;
	error = log_msg(td, &msg);
	if (error != 0)
		goto exit4;

	error = fmaster_get_vnode_info(td, uap->s, &place, &lfd);
	if (error != 0)
		goto exit4;
	switch (place) {
	case FFP_MASTER:
		error = ENOSYS;
		goto exit4;
	case FFP_SLAVE:
		error = sendmsg_slave(td, lfd, &msg, uap->flags);
		break;
	default:
		error = EBADF;
		goto exit4;
	}

exit4:
	free(control, M_TEMP);
exit3:
	for (i = 0; i < iovlen; i++)
		free(iov[i].iov_base, M_TEMP);
exit2:
	free(iov, M_IOV);
exit1:
	free(name, M_TEMP);

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
#endif

int
sys_fmaster_sendmsg(struct thread *td, struct fmaster_sendmsg_args *uap)
{
	struct fmaster_writev_args args;
	struct msghdr msg;
	int error;

	error = copyin(uap->msg, &msg, sizeof(msg));
	if (error != 0)
		return (error);

	args.fd = uap->s;
	args.iovp = msg.msg_iov;
	args.iovcnt = msg.msg_iovlen;
	error = sys_fmaster_writev(td, &args);

	return (error);
}

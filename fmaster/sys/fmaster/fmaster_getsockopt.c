#include <sys/param.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <fsyscall/private/payload.h>
#include <sys/fmaster/fmaster_proto.h>

/*******************************************************************************
 * code for slave
 */

static int
reuseaddr_write_call(struct thread *td, int lfd, int level, int name, socklen_t optlen)
{
	struct payload *payload;
	int error;

	payload = fsyscall_payload_create();
	if (payload == NULL)
		return (ENOMEM);
	error = fsyscall_payload_add_int(payload, lfd);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_int(payload, level);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_int(payload, name);
	if (error != 0)
		goto exit;
	error = fsyscall_payload_add_socklen(payload, optlen);
	if (error != 0)
		goto exit;

	error = fmaster_write_payloaded_command(td, GETSOCKOPT_CALL, payload);
	if (error != 0)
		goto exit;

exit:
	fsyscall_payload_dispose(payload);

	return (error);
}

struct reuseaddr_bonus {
	socklen_t optlen;
	int optval;
};

static int
reuseaddr_callback(struct thread *td, int *retval,
		   payload_size_t *optional_payload_size, void *bonus)
{
	struct reuseaddr_bonus *p;
	int error, optlen_len, optval_len;

	p = (struct reuseaddr_bonus *)bonus;

	error = fmaster_read_socklen(td, &p->optlen, &optlen_len);
	if (error != 0)
		return (error);
	error = fmaster_read_int(td, &p->optval, &optval_len);
	if (error != 0)
		return (error);

	*optional_payload_size = optlen_len + optval_len;

	return (0);
}

static int
reuseaddr_read_return(struct thread *td, void *val, socklen_t *avalsize)
{
	struct reuseaddr_bonus bonus;
	int error;

	error = fmaster_execute_return_optional32(td, GETSOCKOPT_RETURN,
						  reuseaddr_callback, &bonus);
	if (error != 0)
		return (error);

	if (*avalsize < sizeof(int))
		return (ENOPROTOOPT);
	error = copyout(&bonus.optval, val, sizeof(bonus.optval));
	if (error != 0)
		return (error);
	*avalsize = bonus.optlen;

	return (0);
}

static int
reuseaddr_main(struct thread *td, int lfd, int level, int name, void *val, socklen_t *avalsize)
{
	int error;

	error = reuseaddr_write_call(td, lfd, level, name, *avalsize);
	if (error != 0)
		return (error);
	error = reuseaddr_read_return(td, val, avalsize);
	if (error != 0)
		return (error);

	return (0);
}

static int
getsockopt_slave(struct thread *td, int lfd, int level, int name, void *val,
		 socklen_t *avalsize)
{

	if (level != SOL_SOCKET)
		return (ENOPROTOOPT);

	switch (name) {
	case SO_REUSEADDR:
		return (reuseaddr_main(td, lfd, level, name, val, avalsize));
	default:
		break;
	}

	return (ENOPROTOOPT);
}

/*******************************************************************************
 * code for master
 */

static int
getsockopt_master(struct thread *td, int lfd, int level, int name, void *val,
		  socklen_t *avalsize)
{
	int error;

	error = kern_getsockopt(td, lfd, level, name, val, UIO_USERSPACE,
				avalsize);

	return (error);
}

/*******************************************************************************
 * code for pending sockets
 */

static int
getsockopt_pending_sock(struct thread *td, int s, int level, int name,
			void *val, socklen_t *avalsize)
{
	struct fmaster_pending_sock pending_sock;
	socklen_t optlen;
	int error, optval;
	const void *src;

	error = fmaster_get_pending_socket(td, s, &pending_sock);
	if (error != 0)
		return (error);

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_REUSEADDR:
			optval = pending_sock.fps_reuseaddr ? name : 0;
			src = &optval;
			optlen = sizeof(optval);
			break;
		default:
			return (ENOPROTOOPT);
		}
		break;
	default:
		return (ENOPROTOOPT);
	}

	if (*avalsize < optlen)
		return (EINVAL);
	error = copyout(src, val, optlen);
	if (error != 0)
		return (error);
	*avalsize = optlen;

	return (0);
}

/*******************************************************************************
 * shared code
 */

static int
fmaster_getsockopt_main(struct thread *td, int s, int level, int name, void *val, socklen_t *avalsize)
{
	enum fmaster_file_place place;
	int error, fd;

	error = fmaster_get_vnode_info(td, s, &place, &fd);
	if (error != 0)
		return (error);
	switch (place) {
	case FFP_MASTER:
		return (getsockopt_master(td, fd, level, name, val, avalsize));
	case FFP_SLAVE:
		return (getsockopt_slave(td, fd, level, name, val, avalsize));
	case FFP_PENDING_SOCKET:
		error = getsockopt_pending_sock(td, s, level, name, val,
						avalsize);
		return (error);
	default:
		return (EINVAL);
	}
}

int
sys_fmaster_getsockopt(struct thread *td, struct fmaster_getsockopt_args *uap)
{
	struct timeval time_start;
	socklen_t optlen;
	int error, level, name, s;
	const char *sysname = "getsockopt";
	void *avalsize, *val;

	s = uap->s;
	level = uap->level;
	name = uap->name;
	val = uap->val;
	avalsize = uap->avalsize;
	error = copyin(avalsize, &optlen, sizeof(optlen));
	if (error != 0)
		return (error);

	fmaster_log(td, LOG_DEBUG,
		    "%s: started: s=%d, level=0x%x, name=%d (%s), val=%p, avals"
		    "ize=%p (%d)",
		    sysname, s, level, name, fmaster_get_sockopt_name(name),
		    val, avalsize, optlen);
	microtime(&time_start);

	error = fmaster_getsockopt_main(td, s, level, name, val, &optlen);
	if (error != 0)
		goto exit;

	error = copyout(&optlen, avalsize, sizeof(optlen));
	if (error != 0)
		goto exit;

exit:
	fmaster_log_syscall_end(td, sysname, &time_start, error);

	return (error);
}

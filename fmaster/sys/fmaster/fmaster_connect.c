#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/time.h>
#include <sys/un.h>

#include <fsyscall/private/encode.h>
#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_proto.h>

static int
call_un(struct thread *td, int s, struct sockaddr *name, socklen_t namelen)
{
	struct sockaddr_un *sun;
	payload_size_t payload_size;
	size_t name_sun_path_len;
	int error, name_sun_family_len, name_sun_len_len, name_sun_path_len_len;
	int namelen_len, s_len, wfd;
	char name_sun_family_buf[FSYSCALL_BUFSIZE_UINT8];
	char name_sun_len_buf[FSYSCALL_BUFSIZE_UINT8];
	char name_sun_path_len_buf[FSYSCALL_BUFSIZE_UINT64];
	char namelen_buf[FSYSCALL_BUFSIZE_UINT32], *path;
	char s_buf[FSYSCALL_BUFSIZE_INT32];


	s_len = fsyscall_encode_int32(s, s_buf, sizeof(s_buf));
	namelen_len = fsyscall_encode_uint32(namelen, namelen_buf, sizeof(namelen_buf));
	sun = (struct sockaddr_un *)name;
	name_sun_len_len = fsyscall_encode_uint8(sun->sun_len, name_sun_len_buf, sizeof(name_sun_len_buf));
	name_sun_family_len = fsyscall_encode_uint8(sun->sun_family, name_sun_family_buf, sizeof(name_sun_family_buf));
	path = sun->sun_path;
	name_sun_path_len = strlen(path);
	name_sun_path_len_len = fsyscall_encode_uint64(name_sun_path_len, name_sun_path_len_buf, sizeof(name_sun_path_len_buf));

	error = fmaster_write_command(td, CALL_CONNECT);
	if (error != 0)
		return (error);
	payload_size = s_len + namelen_len + name_sun_len_len + name_sun_family_len + name_sun_path_len_len + name_sun_path_len;
	error = fmaster_write_payload_size(td, payload_size);
	if (error != 0)
		return (error);
	wfd = fmaster_wfd_of_thread(td);
	error = fmaster_write(td, wfd, s_buf, s_len);
	if (error != 0)
		return (error);
	error = fmaster_write(td, wfd, namelen_buf, namelen_len);
	if (error != 0)
		return (error);
	error = fmaster_write(td, wfd, name_sun_len_buf, name_sun_len_len);
	if (error != 0)
		return (error);
	error = fmaster_write(td, wfd, name_sun_family_buf, name_sun_family_len);
	if (error != 0)
		return (error);
	error = fmaster_write(td, wfd, name_sun_path_len_buf, name_sun_path_len_len);
	if (error != 0)
		return (error);
	error = fmaster_write(td, wfd, path, name_sun_path_len);
	if (error != 0)
		return (error);

	return (0);
}

typedef int (*call_t)(struct thread *, int, struct sockaddr *, socklen_t);

static int
fmaster_connect_main(struct thread *td, struct fmaster_connect_args *uap)
{
	struct sockaddr_storage sockaddr;
	struct sockaddr *paddr;
	call_t call;
	int error;

	paddr = (struct sockaddr *)&sockaddr;
	error = copyin(uap->name, paddr, uap->namelen);
	if (error != 0)
		return (error);

	switch (paddr->sa_family) {
	case AF_LOCAL:
		call = call_un;
		break;
	default:
		return (EINVAL);
	}

	error = call(td, uap->s, paddr, uap->namelen);
	if (error != 0)
		return (error);
	error = fmaster_execute_return_generic32(td, RET_CONNECT);
	if (error != 0)
		return (error);

	return (0);
}

int
sys_fmaster_connect(struct thread *td, struct fmaster_connect_args *uap)
{
	struct timeval time_start;
	pid_t pid;
	int error;

	pid = td->td_proc->p_pid;
	log(LOG_DEBUG, "fmaster[%d]: connect: started: s=%d, name=%p, namelen=%d\n", pid, uap->s, uap->name, uap->namelen);
	microtime(&time_start);

	error = fmaster_connect_main(td, uap);

	fmaster_log_spent_time(td, "connect: ended", &time_start);

	return (error);
}

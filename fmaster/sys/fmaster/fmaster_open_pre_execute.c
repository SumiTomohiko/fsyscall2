#include <sys/param.h>
#include <sys/types.h>
#include <sys/libkern.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <fsyscall/private/fmaster.h>
#include <sys/fmaster/fmaster_pre_post.h>
#include <sys/fmaster/fmaster_proto.h>

static int
open_master(struct thread *td, struct fmaster_open_args *uap)
{
	int error;

	error = sys_open(td, (struct open_args *)uap);
	if (error != 0)
		return (error);

	return fmaster_return_fd(td, fft_master, td->td_retval[0]);
}

int
fmaster_open_pre_execute(struct thread *td, struct fmaster_open_args *uap, int *error)
{
	const char *dir = "/lib";

	if (strncmp(uap->path, dir, strlen(dir)) == 0) {
		*error = open_master(td, uap);
		return (0);
	}
	if (strcmp(uap->path, "/var/run/ld-elf.so.hints") == 0) {
		*error = open_master(td, uap);
		return (0);
	}

	return (1);
}

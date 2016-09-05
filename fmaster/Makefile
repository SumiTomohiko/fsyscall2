
TOP_DIR=	..

.PATH:		${TOP_DIR}/lib/encode ${TOP_DIR}/lib/payload \
		${TOP_DIR}/lib/read_sockaddr ${TOP_DIR}/lib/select sys/fmaster \
		sys/kern sys/${MACHINE}/${MACHINE} /usr/src/sys/kern

KMOD=		fmaster
SRCS=		elf_machdep.c fmaster_accept.c fmaster_accept4.c \
		fmaster_bind.c fmaster_close.c fmaster_connect.c fmaster_dup.c \
		fmaster_dup2.c fmaster_execve.c fmaster_exit.c fmaster_fcntl.c \
		fmaster_fork.c fmaster_fstatfs.c fmaster_getdirentries.c \
		fmaster_getpeername.c fmaster_getsockname.c \
		fmaster_getsockopt.c fmaster_ioctl.c fmaster_kevent.c \
		fmaster_kqueue.c fmaster_mmap.c fmaster_openat.c \
		fmaster_pipe.c fmaster_poll.c fmaster_recvfrom.c \
		fmaster_recvmsg.c fmaster_select.c fmaster_sendmsg.c \
		fmaster_sendto.c fmaster_setsockopt.c fmaster_sigprocmask.c \
		fmaster_socketpair.c fmaster_syscalls.c fmaster_sysent.c \
		fmaster_subr.c fmaster_thr_exit.c fmaster_thr_new.c \
		fmaster_utimes.c fsyscall_encode.c fsyscall_payload.c \
		fsyscall_read_sockaddr.c fsyscall_select.c imgact_elf64.c \
		kern_exec.c syscall.c
KERNBUILDDIR=	/usr/obj/usr/src/sys/GENERIC
DEBUG_FLAGS=	-g
CFLAGS=		-Isys -I${TOP_DIR}/include -I/usr/src/sys -Wswitch-enum

.include "Makefile.makesyscalls"
.include <bsd.kmod.mk>

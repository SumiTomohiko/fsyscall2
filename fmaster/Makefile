
TOP_DIR=	..

.PATH:		${TOP_DIR}/lib/encode ${TOP_DIR}/lib/select sys/fmaster \
		sys/kern sys/${MACHINE}/${MACHINE} /usr/src/sys/kern

KMOD=		fmaster
SRCS=		elf_machdep.c fmaster_connect.c fmaster_exit.c \
		fmaster_fstatfs.c fmaster_getdirentries.c fmaster_ioctl.c \
		fmaster_mmap.c fmaster_poll.c fmaster_select.c \
		fmaster_syscalls.c fmaster_sysent.c fmaster_subr.c \
		fsyscall_encode.c fsyscall_select.c imgact_elf32.c \
		imgact_elf64.c kern_exec.c syscall.c
KERNBUILDDIR=	/usr/obj/usr/src/sys/GENERIC
CFLAGS=		-Isys -I${TOP_DIR}/include -I/usr/src/sys -Werror

.include "Makefile.makesyscalls"
.include <bsd.kmod.mk>

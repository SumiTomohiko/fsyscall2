
TOP_DIR=	..

.PATH:		${TOP_DIR}/lib/encode fmaster sys/fmaster \
		sys/kern sys/${MACHINE}/${MACHINE} /usr/src/sys/kern

KMOD=		fmaster
SRCS=		elf_machdep.c fmaster_exit.c fmaster_link.c fmaster_syscalls.c \
		fmaster_sysent.c fmaster_subr.c fmaster_write.c \
		fsyscall_encode.c imgact_elf32.c imgact_elf64.c kern_exec.c \
		syscall.c
KERNBUILDDIR=	/usr/obj/usr/src/sys/GENERIC
CFLAGS=		-Isys -I${TOP_DIR}/include

.include <bsd.kmod.mk>

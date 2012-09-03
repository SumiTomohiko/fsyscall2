
.PATH: /usr/src/sys/kern fmaster sys/fmaster sys/kern sys/${MACHINE}/${MACHINE}

KMOD=		fmaster
SRCS=		elf_machdep.c fmaster_creat.c fmaster_exit.c fmaster_io.c \
		fmaster_link.c fmaster_syscalls.c fmaster_sysent.c \
		imgact_elf32.c imgact_elf64.c kern_exec.c syscall.c
KERNBUILDDIR=	/usr/obj/usr/src/sys/GENERIC
TOP_DIR=	..
CFLAGS=		-Isys -I${TOP_DIR}/include

.include <bsd.kmod.mk>

# Makefile for syscall tables
#
# $FreeBSD: src/sys/i386/linux/Makefile,v 1.6.2.1.2.1 2011/11/11 04:20:22 kensmith Exp $

all: sysent

TARGETS = fmaster_sysent.c fmaster_syscall.h fmaster_proto.h \
	  fmaster_syscalls.c fmaster_systrace_args.c

sysent: $(TARGETS)

SYS_DIR = /usr/src/sys

$(TARGETS): $(SYS_DIR)/kern/makesyscalls.sh syscalls.master syscalls.conf
	@: mv -f fmaster_sysent.c fmaster_sysent.c.bak
	@: mv -f fmaster_syscall.h fmaster_syscall.h.bak
	@: mv -f fmaster_proto.h fmaster_proto.h.bak
	@: mv -f fmaster_syscalls.c fmaster_syscalls.c.bak
	@: mv -f fmaster_systrace_args.c fmaster_systrace_args.c.bak
	sh $(SYS_DIR)/kern/makesyscalls.sh syscalls.master syscalls.conf

clean:
	rm -f $(TARGETS)


# When I used tiny_runtime with ../Makefile.cprog, getdirentries(2) failed in
# EFAULT which might mean that a part of buf is at invalid memory region. I do
# not know how to fix it. So I use the standard C library in the OS here.

PROG=		getdirentries
CFLAGS+=	-I../include
WITHOUT_MAN=	yes

.include <bsd.prog.mk>

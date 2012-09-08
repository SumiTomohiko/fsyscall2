
OBJS=	$(PROG).o
SRCS=	$(PROG).asm

all: $(PROG)

$(PROG): $(OBJS)
	ld -o ${.TARGET} $(OBJS)

.include <sys.mk>

.if ${MACHINE_CPUARCH} == "amd64"
FORMAT=	elf64
.else
FORMAT=	elf
.endif

$(OBJS): $(SRCS)
	nasm -f ${FORMAT} -o ${.TARGET} $(SRCS)

clean:
	rm -f $(PROG) $(OBJS)

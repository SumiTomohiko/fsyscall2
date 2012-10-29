
DIR=		..
GENERATOR=	makestattests.sh
MEMBERS=	blksize blocks dev flags gid ino mode nlink rdev size uid
RC_GENERATOR=	makestatrc.sh
SYSCALLS=	fstat lstat stat

TARGETS=
.for syscall in ${SYSCALLS}
.for member in ${MEMBERS}
TARGETS+=	${DIR}/test_${syscall}_${member}
${DIR}/test_${syscall}_${member}: ${GENERATOR}
	./${GENERATOR} ${DIR} ${syscall} ${member}
.endfor
.endfor

.for syscall in ${SYSCALLS}
TARGETS+=	${DIR}/${syscall}.rc
${DIR}/${syscall}.rc: ${RC_GENERATOR}
	./${RC_GENERATOR} ${DIR} ${syscall}
.endfor

all: ${TARGETS}

clean:
	rm -f ${TARGETS}

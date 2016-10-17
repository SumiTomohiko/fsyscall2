
PKG_PATH=	jp/gr/java_conf/neko_daisuki/fsyscall
SLAVE_PATH=	${PKG_PATH}/slave
MAIN_DIR=	src/main
JAVA_DIR=	${MAIN_DIR}/java
RESOURCES_DIR=	${MAIN_DIR}/resources
PKG_DIR=	${JAVA_DIR}/${PKG_PATH}
SLAVE_DIR=	${JAVA_DIR}/${SLAVE_PATH}
JAVA_SRC=	${PKG_DIR}/Command.java ${PKG_DIR}/SyscallResult.java	\
		${SLAVE_DIR}/SlaveHelper.java
SLAVE_RES_DIR=	${RESOURCES_DIR}/${SLAVE_PATH}

all: ${JAVA_SRC}

.SUFFIXES: .java.in .java

.java.in.java:
	$(MAKE) -C .. syscalls

clean:
	rm -f ${JAVA_SRC}

resources:
	mkdir -p ${SLAVE_RES_DIR}
	pwd_mkdb -d ${SLAVE_RES_DIR} master.passwd
	mv ${SLAVE_RES_DIR}/master.passwd .
	rm -f ${SLAVE_RES_DIR}/spwd.db


PKG_DIR=	src/jp/gr/java_conf/neko_daisuki/fsyscall
SLAVE_DIR=	${PKG_DIR}/slave
JAVA_SRC=	${PKG_DIR}/Command.java ${SLAVE_DIR}/Slave.java

all: ${JAVA_SRC}

.SUFFIXES: .java.in .java

.java.in.java:
	cd .. && python3 tools/makesyscalls.py

clean:
	rm -f ${JAVA_SRC}

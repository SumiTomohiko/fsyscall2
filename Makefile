
SLAVEDIR=	fshub fslave
SUBDIR= 	lib fmhub fmaster $(SLAVEDIR) tests
DOCDIR=		doc
JAVADIR=	java
JAVASRCDIR=	java/src/main/java
JAVABUILDER=	./gradlew

test:
	@sync
	@sync
	@sync
	@./run_tests 2>&1 | tee tests.log

doc:
	@cd $(DOCDIR) && $(MAKE)

doc-clean:
	@cd $(DOCDIR) && $(MAKE) clean

install-all: install-master install-slave

install-master:
	@cd fmaster && $(MAKE) install
	@cd fmhub && $(MAKE) install
	@sync
	@sync
	@sync

install-slave:
	@for dir in $(SLAVEDIR);		\
	do					\
		(cd $$dir && $(MAKE) install);	\
	done
	@sync
	@sync
	@sync

java:
	@cd $(JAVADIR) && $(JAVABUILDER) build
	@sync
	@sync
	@sync

java-clean:
	@cd $(JAVADIR) && $(JAVABUILDER) clean

syscalls:
	@python3 tools/makesyscalls.py

tests-clean:
	@cd tests && make clean

prepare:
	@ln -s $(JAVASRCDIR)/jp/gr/java_conf/neko_daisuki/fsyscall \
		jp.gr.java_conf.neko_daisuki.fsyscall
	@ln -s $(JAVASRCDIR)/jp/gr/java_conf/neko_daisuki/fsyscall/io \
		jp.gr.java_conf.neko_daisuki.fsyscall.io
	@ln -s $(JAVASRCDIR)/jp/gr/java_conf/neko_daisuki/fsyscall/slave \
		jp.gr.java_conf.neko_daisuki.fsyscall.slave

.PHONY: $(DOCDIR) $(JAVADIR)

# shortcuts
i: ia
ia: install-all
im: install-master
is: install-slave
j: java

.include <bsd.subdir.mk>

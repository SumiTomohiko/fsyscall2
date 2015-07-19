
SLAVEDIR=	fshub fslave
SUBDIR= 	lib fmhub fmaster $(SLAVEDIR) tests
DOCDIR=		doc
JAVADIR=	java
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

__java-resources__:
	@cd $(JAVADIR) && $(MAKE) resources

tests-clean:
	@cd tests && make clean

.PHONY: $(DOCDIR) $(JAVADIR)

# shortcuts
i: ia
ia: install-all
im: install-master
is: install-slave
ca: clean all

.include "Makefile.gmake"
.include <bsd.subdir.mk>

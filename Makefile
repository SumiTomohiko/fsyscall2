
SLAVEDIR=	fshub fslave
SUBDIR= 	lib fmhub fmaster $(SLAVEDIR) tests
DOCDIR=		doc
JAVADIR=	java

test:
	@sync
	@sync
	@sync
	@./run_tests 2>&1 | tee tests.log

doc:
	@cd $(DOCDIR) && $(MAKE)

doc-clean:
	@cd $(DOCDIR) && $(MAKE) clean

ia: install-all

install-all: install-master install-slave

im: install-master

install-master:
	@cd fmaster && $(MAKE) install
	@cd fmhub && $(MAKE) install
	@sync
	@sync
	@sync

is: install-slave

install-slave:
	@for dir in $(SLAVEDIR);		\
	do					\
		(cd $$dir && $(MAKE) install);	\
	done
	@sync
	@sync
	@sync

java:
	@cd $(JAVADIR) && ant

java-clean:
	@rm -rf $(JAVADIR)/bin

syscalls:
	@python3 tools/makesyscalls.py

.PHONY: $(DOCDIR) $(JAVADIR)

.include <bsd.subdir.mk>

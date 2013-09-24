
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

install-kmod:
	@cd fmaster && $(MAKE) install

install-master:
	@cd fmhub && $(MAKE) install

install-slave:
	@for dir in $(SLAVEDIR);		\
	do					\
		(cd $$dir && $(MAKE) install);	\
	done

java:
	@cd $(JAVADIR) && ant

java-clean:
	@rm -rf $(JAVADIR)/bin

syscalls:
	@python3 tools/makesyscalls.py

.PHONY: $(DOCDIR) $(JAVADIR)

.include <bsd.subdir.mk>

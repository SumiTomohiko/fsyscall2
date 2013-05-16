
SUBDIR= 	lib fmhub fmaster fshub fslave tests
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

java:
	@cd $(JAVADIR) && ant

syscalls:
	@python3 tools/makesyscalls.py

.PHONY: $(DOCDIR) $(JAVADIR)

.include <bsd.subdir.mk>

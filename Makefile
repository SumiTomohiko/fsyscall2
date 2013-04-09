
SUBDIR= lib fmhub fmaster fshub fslave tests
DOCDIR=	doc

test:
	@sync
	@sync
	@sync
	@./run_tests 2>&1 | tee tests.log

doc:
	@cd $(DOCDIR) && $(MAKE)

doc-clean:
	@cd $(DOCDIR) && $(MAKE) clean

.PHONY: $(DOCDIR)

.include <bsd.subdir.mk>

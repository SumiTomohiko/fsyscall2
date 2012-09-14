
SUBDIR= lib fmhub fmaster fshub fslave tests

test:
	@sync
	@sync
	@sync
	@./run_tests 2>&1 | tee tests.log

.include <bsd.subdir.mk>

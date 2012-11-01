%include "do_stat_test.inc"
%include "sys.inc"

; usage: stat path [member]
; Exit status of this program is that of lstat(2). If member is given, this
; program show member of struct stat at stdout.

global _start
_start:
	mov	rbp, rsp

	mov	rax, rdi
	mov	rdi, sys.lstat
	mov	rsi, rax
	call	do_stat_test
	; NOTREACHED

; vim: filetype=nasm

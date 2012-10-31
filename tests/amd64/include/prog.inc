%include "lib.inc"
%include "sys.inc"

%macro test_argc 1
	cmp	qword [rdi], %1
	je	.__main__
	mov	rdi, 127
	call	exit
.__main__:
%endmacro

; usage: mov.atoi dest src base
%macro mov.atoi 3
	mov	rdi, %2
	mov	rsi, %3
	call	atoi
	mov	%1, rax
%endmacro

# vim: filetype=nasm

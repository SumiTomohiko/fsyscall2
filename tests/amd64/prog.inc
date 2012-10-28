%include "lib.inc"
%include "sys.inc"

%macro test_argc 1
	cmp	qword [rdi], %1
	je	.__main__
	mov	rdi, 127
	call	exit
.__main__:
%endmacro

# vim: filetype=nasm

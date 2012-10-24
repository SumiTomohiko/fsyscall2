%include "../sys.inc"

%macro test_argc 1
	cmp	qword [rdi], %1
	je	.__main__
	mov	rdi, 127
	call	exit
.__main__:
%endmacro

extern atoi
extern exit
extern print_num
extern streq
extern strlen

# vim: filetype=nasm

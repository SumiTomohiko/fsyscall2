%include "lib.inc"
%include "macro.inc"

%include "name.inc"

; usage: rdi=struct stat *, rsi=member name
global print_stat_member
print_stat_member:
	prologue	0
%define	sb		r12
%define	member		r13
	mov	sb, rdi
	mov	member, rsi

%include "print.inc"

	epilogue

; vim: filetype=nasm

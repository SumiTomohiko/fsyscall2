%include "lib.inc"

%include "name.inc"

; usage: rdi=struct stat *, rsi=member name
global print_stat_member
print_stat_member:
%define	locals_num	0
	enter	locals_num * 8, 0
	save_registers
%define	sb		r12
%define	member		r13
	mov	sb, rdi
	mov	member, rsi

%include "print.inc"

	restore_registers
	leave
	ret

; vim: filetype=nasm

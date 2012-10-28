%include "lib.inc"
%include "sys.inc"

%include "name.inc"

; usage: rdi=syscall_num, rsi=pargc
; This function never return.
global do_stat_test
do_stat_test:
%define	locals_num	2
	enter	120 + locals_num * 8, 0

%define	syscall_num	qword [rbp - 1 * 8]
%define	pargc		r12
%define	stat		qword [rbp - 2 * 8]
%define sb		rsp
	mov	syscall_num, rdi
	mov	pargc, rsi
%define	argc		qword [pargc]
%define	path		qword [pargc + 2 * 8]
%define	member		qword [pargc + 3 * 8]

	; stat/lstat
	mov	rax, syscall_num
	mov	rdi, path
	mov	rsi, sb
	syscall
	jc	.exit
	cmp	rax, 0
	jne	.exit
	cmp	argc, 2
	je	.exit
	mov	stat, rax

%include "print.inc"

	mov	rax, stat

.exit:
	; exit
	mov	rdi, rax
	call	exit

# vim: filetype=nasm

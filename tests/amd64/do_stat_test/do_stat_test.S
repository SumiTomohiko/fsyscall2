%include "lib.inc"
%include "macro.inc"
%include "print_stat_member.inc"
%include "sys.inc"

; usage: rdi=syscall_num, rsi=pargc
; This function never return.
global do_stat_test
do_stat_test:
	prologue	3
	sub	rsp, sizeof.stat

%define	syscall_num	local(0)
%define	pargc		r12
%define	stat		local(1)
%define sb		local(2)
	mov	syscall_num, rdi
	mov	pargc, rsi
	mov	sb, rsp
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

	mov	rdi, sb
	mov	rsi, member
	call	print_stat_member

	mov	rax, stat

.exit:
	; exit
	mov	rdi, rax
	call	exit

; vim: filetype=nasm

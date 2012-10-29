%include "lib.inc"
%include "print_stat_member.inc"
%include "sys.inc"

; usage: fstat path [member]
; If member is given, this program prints a value of that member.
global _start
_start:
	mov	rbp, rsp

%define	locals_num	2
	sub	rsp, locals_num * 8 + sizeof.stat
%define	pargc		r12
%define	status		qword [rbp - 1 * 8]
%define	fd		qword [rbp - 2 * 8]
%define	sb		rsp
	mov	pargc, rdi
	mov	status, 1

	; open
	mov	rax, sys.open
	mov	rdi, qword [pargc + 2 * 8]
	mov	rsi, 0		; read only
	syscall
	jc	.exit
	cmp	rax, -1
	je	.exit
	mov	fd, rax

	; fstat
	mov	rax, sys.fstat
	mov	rdi, fd
	mov	rsi, sb
	syscall
	mov	status, rax
	jc	.exit
	cmp	status, 0
	jne	.exit

	cmp	qword [pargc], 3
	jne	.close
	mov	rdi, sb
	mov	rsi, qword [pargc + 3 * 8]
	call	print_stat_member

.close:
	; close
	mov	rax, sys.close
	mov	rdi, fd
	syscall
	mov	status, rax
	jc	.exit
	cmp	status, 0
	jne	.exit
	mov	status, 0

.exit:
	; exit
	mov	rdi, status
	call	exit

; vim: filetype=nasm

%include "prog.inc"

; Usage: close fd

global _start
_start:
	mov	rbp, rsp
	test_argc	2
	sub	rsp, 2 * 8
%define	fd	qword [rbp - 1 * 8]
%define status	qword [rbp - 2 * 8]

	mov	rdi, [rdi + 2 * 8]
	mov	rsi, 10
	call	atoi
	mov	fd, rax

	; close
	mov	rax, sys.close
	mov	rdi, fd
	syscall
	jc	.error
	mov	status, rax

	; exit
	mov	rdi, status
	call	exit

.error:
	mov	rdi, 128
	call	exit

; vim: filetype=nasm

%include "prog.inc"

; Usage: close_twice fd
; This program closes the given file descriptor twice. If second closing failed
; for EBADF, this exits with status of zero (successfully).

global _start
_start:
	mov	rbp, rsp
	test_argc	2
	sub	rsp, 2 * 8
%define	fd	qword [rbp - 1 * 8]
%define	status	qword [rbp - 2 * 8]

	mov	rdi, [rdi + 2 * 8]
	mov	rsi, 10
	call	atoi
	mov	fd, rax

	mov	status, 1

	; close
	mov	rax, sys.close
	mov	rdi, fd
	syscall
	jc	.error

	; close
	mov	rax, sys.close
	mov	rdi, fd
	syscall
	jnc	.error
	mov	status, rax
	cmp	rax, 9	; EBADF
	jne	.error

	mov	status, 0

.error:
	mov	rdi, status
	call	exit

; vim: filetype=nasm

%include "prog.inc"

; Usage: open path flags mode
; flags must be hexadecimal, mode must be octal.

global _start
_start:
	mov	rbp, rsp
	test_argc	4

	sub	rsp, 4 * 8
%define	path	qword [rbp - 8]
%define	flags	qword [rbp - 2 * 8]
%define	mode	qword [rbp - 3 * 8]
%define	fd	qword [rbp - 4 * 8]

	mov	rax, [rdi + 2 * 8]
	mov	path, rax

	push	rdi
	mov	rdi, [rdi + 3 * 8]
	mov	rsi, 16
	call	atoi
	mov	flags, rax
	pop	rdi

	push	rdi
	mov	rdi, [rdi + 4 * 8]
	mov	rsi, 8
	call	atoi
	mov	mode, rax
	pop	rdi

	; open
	mov	rax, sys.open
	mov	rdi, path
	mov	rsi, flags
	mov	rdx, mode
	syscall
	jc	.error
	mov	fd, rax

	; exit
	mov	rdi, fd
	call	exit

.error:
	mov	rdi, -1
	call	exit

; vim: filetype=nasm

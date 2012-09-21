%include "../amd64.inc"

; Usage: open path flags mode
; flags must be hexadecimal, mode must be octal.

global _start
_start:
	mov	rbp, rsp

	cmp	qword [rdi], 4
	je	.main
	mov	rdi, 127
	call	exit
	; NOTREACHED

.main:
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
	mov	fd, rax

	; exit
	mov	rdi, fd
	call	exit

# vim: filetype=nasm

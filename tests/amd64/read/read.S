%include "prog.inc"

; Usage: read path
; This is kind of cat. This writes contents of <path> to stdout.

section	.bss

%define	nbytes	256
buf:	resb nbytes

section	.text

global _start
_start:
	mov	rbp, rsp
	sub	rsp, 4 * 8
%define	path	qword [rbp - 8]
%define	fd	qword [rbp - 2 * 8]
%define	status	qword [rbp - 3 * 8]
%define	error	qword [rbp - 4 * 8]

	mov	rax, [rdi + 2 * 8]
	mov	path, rax

	; open
	mov	error, 1
	mov	rax, sys.open
	mov	rdi, path
	mov	rsi, 0
	syscall
	jc	.exit
	mov	fd, rax

.begin:
	; read
	mov	error, 2
	mov	rax, sys.read
	mov	rdi, fd
	mov	rsi, buf
	mov	rdx, nbytes
	syscall
	jc	.exit
	mov	status, rax
	cmp	status, 0
	je	.end
	cmp	status, -1
	je	.exit

	; write
	mov	error, 3
	mov	rax, sys.write
	mov	rdi, 1		; stdout
	mov	rsi, buf
	mov	rdx, status
	syscall
	jc	.exit
	jmp	.begin

.end:
	; close
	mov	error, 4
	mov	rax, sys.close
	mov	rdi, fd
	syscall
	jc	.exit

	mov	error, 0

.exit:
	mov	rdi, error
	call	exit

# vim: filetype=nasm

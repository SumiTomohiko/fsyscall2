%include "prog.inc"

; usage: readlink path
global _start
_start:
	mov	rbp, rsp
%define	locals_num	1
%define	bufsize		256
	sub	rsp, locals_num * 8 + bufsize
%define	path	r12
%define	buf	rsp
%define	size	qword [rbp - 1 * 8]
	mov	path, qword [rdi + 2 * 8]

	; readlink
	mov	rax, sys.readlink
	mov	rdi, path
	mov	rsi, buf
	mov	rdx, bufsize
	syscall
	jc	.error
	mov	size, rax

	; write
	mov	rax, sys.write
	mov	rdi, sys.stdout
	mov	rsi, buf
	mov	rdx, bufsize
	syscall
	jc	.error

	mov	rdi, size
	jmp	.exit
.error:
	mov	rdi, 255
.exit:
	call	exit

; vim: filetype=nasm

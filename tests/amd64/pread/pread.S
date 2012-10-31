%include "prog.inc"

; usage: pread path offset
global _start
_start:
	mov	rbp, rsp
	mov	r12, rdi
%define	path	qword [r12 + 2 * 8]
%define	locals	3
%define	bufsize	256
	sub	rsp, locals * 8 + bufsize
%define	offset	qword [rbp - 1 * 8]
%define	fd	qword [rbp - 2 * 8]
%define	size	qword [rbp - 3 * 8]
%define	buf	rsp
	mov.atoi	offset, qword [r12 + 3 * 8], 10

	; open
	mov	rax, sys.open
	mov	rdi, path
	mov	rsi, flags.readonly
	syscall
	jc	.error
	cmp	rax, -1
	je	.error
	mov	fd, rax

	; pread
	mov	rax, sys.pread
	mov	rdi, fd
	mov	rsi, buf
	mov	rdx, bufsize
	mov	r10, offset
	syscall
	jc	.error
	cmp	rax, -1
	je	.error
	mov	size, rax

	; close
	mov	rax, sys.close
	mov	rdi, fd
	syscall
	jc	.error
	cmp	rax, -1
	je	.error

	; write
	mov	rax, sys.write
	mov	rdi, sys.stdout
	mov	rsi, buf
	mov	rdx, size
	syscall
	jc	.error
	cmp	rax, -1
	je	.error

	mov	rdi, size
	jmp	.exit

.error:
	mov	rdi, -1

.exit:
	call	exit

; vim: filetype=nasm

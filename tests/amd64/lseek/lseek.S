%include "prog.inc"

; usage: lseek path skip offset whence
; This program opens _path_, and reads first _skip_ bytes to drop. Then this
; calls lseek(2) with _offset_ and _whence_. SEEK_SET for _whence_ is zero,
; SEEK_CUR is one and SEEK_END is two. Finally, this program reads all from
; current offset to write them to stdout. Exit status of this is that of
; lseek(2).
global _start
_start:
	mov	rbp, rsp
	mov	r12, rdi
%define	path	qword [r12 + 2 * 8]
%define	locals	7
%define	bufsize	8
	sub	rsp, locals * 8 + bufsize
%define	skip	qword [rbp - 1 * 8]
%define	offset	qword [rbp - 2 * 8]
%define	whence	qword [rbp - 3 * 8]
%define	fd	qword [rbp - 4 * 8]
%define	status	qword [rbp - 5 * 8]
%define	nbytes	qword [rbp - 6 * 8]
%define	buf	qword [rbp - 7 * 8]
%define	base	10
	mov.atoi	skip, qword [r12 + 3 * 8], base
	mov.atoi	offset, qword [r12 + 4 * 8], base
	mov.atoi	whence, qword [r12 + 5 * 8], base
	mov	buf, rsp
	sub	rsp, skip
%define	skipbuf	rsp

	; open
	mov	rax, sys.open
	mov	rdi, path
	mov	rsi, flags.readonly 
	syscall
	jc	.error
	cmp	rax, 0
	jl	.error
	mov	fd, rax

	; read
	mov	rax, sys.read
	mov	rdi, fd
	mov	rsi, skipbuf
	mov	rdx, skip
	syscall
	jc	.error
	cmp	rax, -1
	je	.error

	; lseek
	mov	rax, sys.lseek
	mov	rdi, fd
	mov	rsi, offset
	mov	rdx, whence
	syscall
	jc	.error
	cmp	rax, -1
	je	.error
	mov	status, rax

.begin:
	; read
	mov	rax, sys.read
	mov	rdi, fd
	mov	rsi, buf
	mov	rdx, bufsize
	syscall
	jc	.error
	cmp	rax, -1
	je	.error
	cmp	rax, 0
	je	.end
	mov	nbytes, rax

	; write
	mov	rax, sys.write
	mov	rdi, sys.stdout
	mov	rsi, buf
	mov	rdx, nbytes
	syscall
	jc	.error
	cmp	rax, -1
	je	.error
	; This code assumes that write(2) writes all of _buf_.

	jmp	.begin
.end:

	; close
	mov	rax, sys.close
	mov	rdi, fd
	syscall
	jc	.error
	cmp	rax, -1
	je	.error

	jmp	.exit

.error:
	mov	status, 255

.exit:
	; exit
	mov	rdi, status
	call	exit

; vim: filetype=nasm

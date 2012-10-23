%include "../test.inc"

; usage: stat path [member]
; Exit status of this program is that of stat(2). If member is given, this
; program show member of struct stat at stdout.

%include "name.inc"

digits:	db	"0123456789"

print_num:
%define	bufsize	32
%define	locals	5
	enter	locals * 8, 0

%define	buf	rbp - (bufsize + locals * 8)
%define	bufend	qword [rbp - 5 * 8]
%define	len	qword [rbp - 4 * 8]
%define	p	qword [rbp - 3 * 8]
%define	base	qword [rbp - 2 * 8]
%define	n	qword [rbp - 8]
	mov	base, 10
	mov	n, rdi
	mov	p, rsp
	dec	p
	mov	rax, p
	mov	byte [rax], 0
	mov	bufend, rsp
	sub	rsp, bufsize

	cmp	n, 0
	jne	.begin
	dec	p
	mov	rax, p
	mov	byte [rax], '0'
	jmp	.end

.begin:
	cmp	n, 0
	je	.end
	mov	rdx, 0
	mov	rax, n
	div	base
	mov	n, rax
	dec	p
	mov	rax, p
	add	rdx, digits
	mov	dl, byte [rdx]
	mov	byte [rax], dl
	jmp	.begin
.end:

	mov	rax, bufend
	sub	rax, p
	mov	len, rax

	; write
	mov	rax, sys.write
	mov	rdi, sys.stdout
	mov	rsi, p
	mov	rdx, len
	syscall

	leave
	ret

global _start
_start:
	mov	rbp, rsp

%define	pargc	r12
%define	argc	qword [pargc]
%define	path	qword [pargc + 2 * 8]
%define	member	qword [pargc + 3 * 8]
%define sb	rsp
%define	stat	qword [rsp + 128]	; stat is 8-byte aligned.
	mov	pargc, rdi
	sub	rsp, 128 + 8

	; stat
	mov	rax, sys.stat
	mov	rdi, path
	mov	rsi, sb
	syscall
	jc	.exit
	cmp	rax, 0
	jne	.exit
	cmp	argc, 2
	je	.exit
	mov	stat, rax

%include "print.inc"

	mov	rax, stat

.exit:
	; exit
	mov	rdi, rax
	call	exit

# vim: filetype=nasm

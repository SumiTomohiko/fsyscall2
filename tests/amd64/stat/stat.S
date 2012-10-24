%include "../test.inc"

; usage: stat path [member]
; Exit status of this program is that of stat(2). If member is given, this
; program show member of struct stat at stdout.

%include "name.inc"

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

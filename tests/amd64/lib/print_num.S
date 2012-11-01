%include "sys.inc"

digits:	db	"0123456789"

; usage: rdi=number
global print_num
print_num:
%define	bufsize	32
%define	locals	5
	enter	locals * 8, 0
	save_registers

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

	add	rsp, bufsize
	restore_registers
	leave
	ret

# vim: filetype=nasm

%include "macro.inc"
%include "sys.inc"

digits:	db	"0123456789"

; usage: rdi=number
global print_num
print_num:
	prologue	5

%define	bufend	local(4)
%define	len	local(3)
%define	p	local(2)
%define	base	local(1)
%define	n	local(0)
	mov	base, 10
	mov	n, rdi
	mov	p, rsp
	dec	p
	mov	rax, p
	mov	byte [rax], 0
	mov	bufend, rsp
%define	bufsize	32
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
	epilogue

# vim: filetype=nasm

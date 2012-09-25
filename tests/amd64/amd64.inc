
%define	sys.exit	1
%define	sys.read	3
%define	sys.write	4
%define	sys.open	5
%define	sys.close	6

%macro test_argc 1
	cmp	qword [rdi], %1
	je	.__main__
	mov	rdi, 127
	call	exit
.__main__:
%endmacro

; ******************************************************************************
; Usage: rdi=string
strlen:
	enter	0, 0

	mov	rax, 0
	mov	rbx, rdi
.begin:
	cmp	byte [rbx], 0
	je	.end
	inc	rax
	inc	rbx
	jmp	.begin

.end:
	leave
	ret

; ******************************************************************************
; Usage: rdi=status
exit:
	enter	0, 0

	mov	rax, sys.exit
	syscall
	; NOTREACHED

	leave
	ret

; ******************************************************************************
; Usage: rdi=string, rsi=base
atoi:
	enter	0, 0

	mov	r8, 0
	mov	rbx, rdi
.begin:
	mov	cl, [rbx]
	cmp	cl, 0
	je	.end
	sub	cl, '0'
	movzx	r9, cl
	mov	rax, rsi
	mul	r8
	mov	r8, rax
	add	r8, r9

	inc	rbx
	jmp	.begin

.end:
	mov	rax, r8
	leave
	ret

# vim: filetype=nasm

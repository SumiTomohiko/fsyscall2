
%define	sys.stdin	0
%define	sys.stdout	1
%define	sys.stderr	2

%define	sys.exit	1
%define	sys.read	3
%define	sys.write	4
%define	sys.open	5
%define	sys.close	6
%define	sys.access	33
%define	sys.stat	188

%macro test_argc 1
	cmp	qword [rdi], %1
	je	.__main__
	mov	rdi, 127
	call	exit
.__main__:
%endmacro

; ******************************************************************************
; Usage: rdi=string, rsi=string
; If two strings are same, streq will return zero. Otherwise, non-zero.
streq:
	enter	0, 0
%define	p	rdi
%define	q	rsi

; retval = 1;
; while (*p == *q) {
;     if (*p == '\0') {
;         retval = 0;
;         break;
;     }
;     p++;
;     q++;
; }
; return (retval);
	mov	rax, 1
.begin:
	mov	al, byte [p]
	cmp	al, byte [q]
	jne	.end
	cmp	al, 0
	jne	.inc
	mov	rax, 0
	jmp	.end
.inc:
	inc	p
	inc	q
	jmp	.begin
.end:

%undef	q
%undef	p
	leave
	ret

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

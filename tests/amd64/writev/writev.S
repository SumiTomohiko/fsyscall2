%include "prog.inc"

; usage: writev fd [string...]

main:
	prologue	8
%define	argc	local(0)
%define	argv	local(1)
%define	fd	local(2)
%define	iovcnt	local(3)
%define	iov	local(4)
%define	i	local(5)
%define	s	local(6)
%define	len	local(7)
	mov	argc, rdi
	mov	argv, rsi

	; fd = atoi(argv[1])
	mov	rax, argv
	add	rax, 8
	mov	rdi, [rax]
	mov	rsi, 10
	call	atoi
	mov	fd, rax

	; iovcnt = argc - 2
	mov	rax, argc
	sub	rax, 2
	mov	iovcnt, rax

	; iov = alloca(sizeof(struct iov) * iovcnt)
	mov	rdx, 0
	mov	rax, sizeof.iov
	mul	iovcnt
	sub	rsp, rax
	mov	iov, rsp

	mov	i, 0
.begin:
	mov	rax, iovcnt
	cmp	i, rax
	je	.end

	; s = argv[i + 2]
	mov	rdx, 0
	mov	rax, i
	add	rax, 2
	mov	r8, 8
	mul	r8
	add	rax, argv
	mov	rax, [rax]
	mov	s, rax

	; len = strlen(s)
	mov	rdi, s
	call	strlen
	mov	len, rax

	; p = &iov[i]
	mov	rdx, 0
	mov	rax, sizeof.iov
	mul	i
	add	rax, iov
	; p->iov_base = s
	mov	r8, s
	mov	qword [rax], r8
	; p->iov_len = len
	add	rax, 8
	mov	r8, len
	mov	qword [rax], r8

	inc	i
	jmp	.begin
.end:

	; writev
	mov	rax, sys.writev
	mov	rdi, fd
	mov	rsi, iov
	mov	rdx, iovcnt
	syscall
	jc	.error

	jmp	.exit
.error:
	mov	rax, 255
.exit:
	epilogue

global _start
_start:
	mov	rbp, rsp

	mov	rax, rdi
	mov	rdi, qword [rax]
	lea	rsi, [rax + 8]
	call	main

	; exit
	mov	rdi, rax
	call	exit

; vim: filetype=nasm

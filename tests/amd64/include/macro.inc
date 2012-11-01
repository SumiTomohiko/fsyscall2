
%macro test_argc 1
	cmp	qword [rdi], %1
	je	.__main__
	mov	rdi, 127
	call	exit
.__main__:
%endmacro

; usage: mov.atoi dest src base
%macro mov.atoi 3
	mov	rdi, %2
	mov	rsi, %3
	call	atoi
	mov	%1, rax
%endmacro

%macro save_registers 0
	push	r12
	push	r13
	push	r14
	push	r15
%endmacro

%macro restore_registers 0
	pop	r15
	pop	r14
	pop	r13
	pop	r12
%endmacro

%define	callee_save_registers_num	4

%macro prologue 1
	push	rbp
	mov	rbp, rsp
	save_registers
	sub	rsp, %1 * 8
%endmacro

%macro epilogue 0
	lea	rsp, [rbp - callee_save_registers_num * 8]
	restore_registers
	pop	rbp
	ret
%endmacro

%define	local(n)	qword [rbp - (callee_save_registers_num + n + 1) * 8]

; vim: filetype=nasm


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
%define	sys.fstat	189
%define	sys.lstat	190
%define	sys.issetugid	253

%define	sizeof.stat	120

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

# vim: filetype=nasm

%ifndef SYS_INC_INCLUDED
%define	SYS_INC_INCLUDED

%define	sys.stdin	0
%define	sys.stdout	1
%define	sys.stderr	2

%define	sys.exit		1
%define	sys.fork		2
%define	sys.read		3
%define	sys.write		4
%define	sys.open		5
%define	sys.close		6
%define	sys.wait4		7
%define	sys.chdir		12
%define	sys.getpid		20
%define	sys.getuid		24
%define	sys.geteuid		25
%define	sys.accept		30
%define	sys.getpeername		31
%define	sys.getsockname		32
%define	sys.access		33
%define	sys.kill		37
%define	sys.dup			41
%define	sys.getegid		43
%define	sys.getgid		47
%define	sys.ioctl		54
%define	sys.readlink		58
%define	sys.execve		59
%define	sys.dup2		90
%define	sys.fcntl		92
%define	sys.select		93
%define	sys.socket		97
%define	sys.connect		98
%define	sys.bind		104
%define	sys.listen		106
%define	sys.gettimeofday	116
%define	sys.writev		121
%define	sys.stat		188
%define	sys.fstat		189
%define	sys.lstat		190
%define	sys.getdirentries	196
%define	sys.poll		209
%define	sys.issetugid		253
%define	sys.sigprocmask		340
%define	sys.getresuid		360
%define	sys.getresgid		361
%define	sys.fstatfs		397
%define	sys.sigaction		416
%define	sys.sigwait		429
%define	sys.pread		475
%define	sys.lseek		478

%define	sizeof.iov	(2 * 8)
%define	sizeof.stat	120

%define	flags.readonly	0

%endif
; vim: filetype=nasm

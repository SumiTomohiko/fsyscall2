
%define	sys.stdin	0
%define	sys.stdout	1
%define	sys.stderr	2

%define	sys.exit	1
%define	sys.read	3
%define	sys.write	4
%define	sys.open	5
%define	sys.close	6
%define	sys.access	33
%define	sys.ioctl	54
%define	sys.readlink	58
%define	sys.select	93
%define	sys.writev	121
%define	sys.stat	188
%define	sys.fstat	189
%define	sys.lstat	190
%define	sys.issetugid	253
%define	sys.pread	475
%define	sys.lseek	478

%define	sizeof.iov	(2 * 8)
%define	sizeof.stat	120

%define	flags.readonly	0

# vim: filetype=nasm

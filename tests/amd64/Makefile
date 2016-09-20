
LIBDIR=	do_stat_test print_stat_member lib tiny_runtime
SUBDIR=	${LIBDIR} SIGKILL_poll SIGKILL_wait4 accept accept4 \
	accept4_SOCK_CLOEXEC accept4_SOCK_NONBLOCK access \
	ancillary_from_client bind chdir chdir_access chdir_error chdir_lstat \
	chdir_open chdir_readlink chdir_stat chmod chmod_error close \
	close_pending_sock close_twice connect dup dup2_closed2closed \
	dup2_closed2master dup2_closed2slave dup2_master2closed \
	dup2_master2master dup2_master2slave dup2_nothing dup2_slave2closed \
	dup2_slave2master dup2_slave2slave dup2_to_pending_sock dup_and_close \
	execve exit fcntl fcntl_accmode_dir fcntl_accmode_kqueue \
	fcntl_accmode_pending_sock fcntl_accmode_read fcntl_accmode_readwrite \
	fcntl_accmode_sock fcntl_accmode_write fcntl_pending_sock \
	fcntl_pending_sock2 fdpassing fdpassing2 fdpassing_EBADF fork fstat \
	fstat_bind fstatfs fstatfs_pending_sock fsync getdirentries \
	getdirentries_pending_sock getegid geteuid getgid getpeername_error \
	getpeername_family getpeername_path getpeername_server getpid \
	getresgid_egid getresgid_rgid getresgid_sgid getresuid_ruid \
	getresuid_euid getresuid_suid getsockname_family getsockname_server \
	getsockopt_pending_sock getsockopt_slave gettimeofday_dsttime \
	gettimeofday_minuteswest gettimeofday_sec gettimeofday_usec getuid \
	ioctl issetugid kill listen lseek lstat mkdir open open_EISDIR \
	open_ENOENT open_O_CLOEXEC open_O_CLOEXEC2 open_O_DIRECTORY open_pwddb \
	openat openat_EBADF openat_abspath openat_perm openat_sock pipe pipe2 \
	pipe2_O_CLOEXEC pipe2_O_NONBLOCK poll_POLLHUP poll_POLLHUP2 poll_bind \
	poll_ignore_fd poll_ignore_fd_master poll_ignore_fd_master_slave \
	poll_ignore_fd_slave poll_in poll_master poll_master_slave_blocking \
	poll_master_slave_blocking2 poll_master_slave_nonblocking \
	poll_master_slave_nonblocking2 poll_out poll_pending_sock poll_timeout \
	pread read readlink recvmsg_controllen_for_nothing recvmsg_master \
	recvmsg_not_socket_slave recvmsg_pending_sock recvmsg_slave rename \
	rmdir select select2 select_master sendmsg_master \
	sendmsg_not_socket_slave sendmsg_pending_sock sendmsg_slave setsockopt \
	shutdown_EBADF shutdown_EINVAL shutdown_ENOTCONN shutdown_ENOTSOCK \
	shutdown_SHUT_RD shutdown_SHUT_RDWR shutdown_SHUT_WR shutdown_read \
	shutdown_write sigprocmask socket socketpair stat stat_ENOENT stat_dir \
	thr_new umask unixsock_creds unlink utimes utimes_null wait4_ECHILD \
	wait4_WNOHANG wait4_multithread wait4_rusage wait4_status \
	wait4_successful write writev

.include <bsd.subdir.mk>

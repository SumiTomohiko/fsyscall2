#if !defined(FSYSCALL_PRIVATE_COMMAND_CODE_H_INCLUDED)
#define	FSYSCALL_PRIVATE_COMMAND_CODE_H_INCLUDED

#define	KEEPALIVE			2

#define	EXIT_CALL			42
#define	EXIT_RETURN			43
#define	READ_CALL			44
#define	READ_RETURN			45
#define	WRITE_CALL			46
#define	WRITE_RETURN			47
#define	OPEN_CALL			48
#define	OPEN_RETURN			49
#define	CLOSE_CALL			50
#define	CLOSE_RETURN			51
#define	LINK_CALL			52
#define	LINK_RETURN			53
#define	GETPID_CALL			54
#define	GETPID_RETURN			55
#define	GETUID_CALL			56
#define	GETUID_RETURN			57
#define	GETEUID_CALL			58
#define	GETEUID_RETURN			59
#define	ACCESS_CALL			60
#define	ACCESS_RETURN			61
#define	DUP_CALL			62
#define	DUP_RETURN			63
#define	GETEGID_CALL			64
#define	GETEGID_RETURN			65
#define	GETGID_CALL			66
#define	GETGID_RETURN			67
#define	IOCTL_CALL			68
#define	IOCTL_RETURN			69
#define	READLINK_CALL			70
#define	READLINK_RETURN			71
#define	FCNTL_CALL			72
#define	FCNTL_RETURN			73
#define	SELECT_CALL			74
#define	SELECT_RETURN			75
#define	WRITEV_CALL			76
#define	WRITEV_RETURN			77
#define	STAT_CALL			78
#define	STAT_RETURN			79
#define	FSTAT_CALL			80
#define	FSTAT_RETURN			81
#define	LSTAT_CALL			82
#define	LSTAT_RETURN			83
#define	GETDIRENTRIES_CALL		84
#define	GETDIRENTRIES_RETURN		85
#define	ISSETUGID_CALL			86
#define	ISSETUGID_RETURN		87
#define	FSTATFS_CALL			88
#define	FSTATFS_RETURN			89
#define	PREAD_CALL			90
#define	PREAD_RETURN			91
#define	MMAP_CALL			92
#define	MMAP_RETURN			93
#define	LSEEK_CALL			94
#define	LSEEK_RETURN			95
#define	SOCKET_CALL			96
#define	SOCKET_RETURN			97
#define	CONNECT_CALL			98
#define	CONNECT_RETURN			99
#define	POLL_CALL			100
#define	POLL_RETURN			101
#define	RECVFROM_CALL			102
#define	RECVFROM_RETURN			103
#define	PIPE_CALL			104
#define	PIPE_RETURN			105
#define	FORK_CALL			106
#define	FORK_RETURN			107
#define	WAIT4_CALL			108
#define	WAIT4_RETURN			109
#define	UNLINK_CALL			110
#define	UNLINK_RETURN			111
#define	CHDIR_CALL			112
#define	CHDIR_RETURN			113
#define	FCHDIR_CALL			114
#define	FCHDIR_RETURN			115
#define	MKNOD_CALL			116
#define	MKNOD_RETURN			117
#define	CHMOD_CALL			118
#define	CHMOD_RETURN			119
#define	CHOWN_CALL			120
#define	CHOWN_RETURN			121
#define	MOUNT_CALL			122
#define	MOUNT_RETURN			123
#define	UNMOUNT_CALL			124
#define	UNMOUNT_RETURN			125
#define	SETUID_CALL			126
#define	SETUID_RETURN			127
#define	PTRACE_CALL			128
#define	PTRACE_RETURN			129
#define	RECVMSG_CALL			130
#define	RECVMSG_RETURN			131
#define	SENDMSG_CALL			132
#define	SENDMSG_RETURN			133
#define	ACCEPT_CALL			134
#define	ACCEPT_RETURN			135
#define	GETPEERNAME_CALL		136
#define	GETPEERNAME_RETURN		137
#define	GETSOCKNAME_CALL		138
#define	GETSOCKNAME_RETURN		139
#define	CHFLAGS_CALL			140
#define	CHFLAGS_RETURN			141
#define	FCHFLAGS_CALL			142
#define	FCHFLAGS_RETURN			143
#define	SYNC_CALL			144
#define	SYNC_RETURN			145
#define	KILL_CALL			146
#define	KILL_RETURN			147
#define	GETPPID_CALL			148
#define	GETPPID_RETURN			149
#define	PROFIL_CALL			150
#define	PROFIL_RETURN			151
#define	KTRACE_CALL			152
#define	KTRACE_RETURN			153
#define	GETLOGIN_CALL			154
#define	GETLOGIN_RETURN			155
#define	SETLOGIN_CALL			156
#define	SETLOGIN_RETURN			157
#define	ACCT_CALL			158
#define	ACCT_RETURN			159
#define	REBOOT_CALL			160
#define	REBOOT_RETURN			161
#define	REVOKE_CALL			162
#define	REVOKE_RETURN			163
#define	SYMLINK_CALL			164
#define	SYMLINK_RETURN			165
#define	EXECVE_CALL			166
#define	EXECVE_RETURN			167
#define	UMASK_CALL			168
#define	UMASK_RETURN			169
#define	CHROOT_CALL			170
#define	CHROOT_RETURN			171
#define	MSYNC_CALL			172
#define	MSYNC_RETURN			173
#define	VFORK_CALL			174
#define	VFORK_RETURN			175
#define	OVADVISE_CALL			176
#define	OVADVISE_RETURN			177
#define	GETGROUPS_CALL			178
#define	GETGROUPS_RETURN		179
#define	SETGROUPS_CALL			180
#define	SETGROUPS_RETURN		181
#define	GETPGRP_CALL			182
#define	GETPGRP_RETURN			183
#define	SETPGID_CALL			184
#define	SETPGID_RETURN			185
#define	SETITIMER_CALL			186
#define	SETITIMER_RETURN		187
#define	GETITIMER_CALL			188
#define	GETITIMER_RETURN		189
#define	DUP2_CALL			190
#define	DUP2_RETURN			191
#define	FSYNC_CALL			192
#define	FSYNC_RETURN			193
#define	SETPRIORITY_CALL		194
#define	SETPRIORITY_RETURN		195
#define	GETPRIORITY_CALL		196
#define	GETPRIORITY_RETURN		197
#define	BIND_CALL			198
#define	BIND_RETURN			199
#define	SETSOCKOPT_CALL			200
#define	SETSOCKOPT_RETURN		201
#define	LISTEN_CALL			202
#define	LISTEN_RETURN			203
#define	GETTIMEOFDAY_CALL		204
#define	GETTIMEOFDAY_RETURN		205
#define	GETRUSAGE_CALL			206
#define	GETRUSAGE_RETURN		207
#define	GETSOCKOPT_CALL			208
#define	GETSOCKOPT_RETURN		209
#define	READV_CALL			210
#define	READV_RETURN			211
#define	SETTIMEOFDAY_CALL		212
#define	SETTIMEOFDAY_RETURN		213
#define	FCHMOD_CALL			214
#define	FCHMOD_RETURN			215
#define	FCHOWN_CALL			216
#define	FCHOWN_RETURN			217
#define	SETREUID_CALL			218
#define	SETREUID_RETURN			219
#define	SETREGID_CALL			220
#define	SETREGID_RETURN			221
#define	RENAME_CALL			222
#define	RENAME_RETURN			223
#define	FLOCK_CALL			224
#define	FLOCK_RETURN			225
#define	MKFIFO_CALL			226
#define	MKFIFO_RETURN			227
#define	SENDTO_CALL			228
#define	SENDTO_RETURN			229
#define	SHUTDOWN_CALL			230
#define	SHUTDOWN_RETURN			231
#define	SOCKETPAIR_CALL			232
#define	SOCKETPAIR_RETURN		233
#define	MKDIR_CALL			234
#define	MKDIR_RETURN			235
#define	RMDIR_CALL			236
#define	RMDIR_RETURN			237
#define	UTIMES_CALL			238
#define	UTIMES_RETURN			239
#define	ADJTIME_CALL			240
#define	ADJTIME_RETURN			241
/*#define	SETSID_CALL		242*/
/*#define	SETSID_RETURN		243*/
#define	QUOTACTL_CALL			244
#define	QUOTACTL_RETURN			245
#define	NLM_SYSCALL_CALL		246
#define	NLM_SYSCALL_RETURN		247
#define	NFSSVC_CALL			248
#define	NFSSVC_RETURN			249
#define	LGETFH_CALL			250
#define	LGETFH_RETURN			251
#define	GETFH_CALL			252
#define	GETFH_RETURN			253
#define	RTPRIO_CALL			254
#define	RTPRIO_RETURN			255
#define	SEMSYS_CALL			256
#define	SEMSYS_RETURN			257
#define	MSGSYS_CALL			258
#define	MSGSYS_RETURN			259
#define	SHMSYS_CALL			260
#define	SHMSYS_RETURN			261
#define	SETFIB_CALL			262
#define	SETFIB_RETURN			263
#define	NTP_ADJTIME_CALL		264
#define	NTP_ADJTIME_RETURN		265
#define	SETGID_CALL			266
#define	SETGID_RETURN			267
#define	SETEGID_CALL			268
#define	SETEGID_RETURN			269
#define	SETEUID_CALL			270
#define	SETEUID_RETURN			271
#define	PATHCONF_CALL			272
#define	PATHCONF_RETURN			273
#define	FPATHCONF_CALL			274
#define	FPATHCONF_RETURN		275
/*#define	GETRLIMIT_CALL		276*/
/*#define	GETRLIMIT_RETURN	277*/
/*#define	SETRLIMIT_CALL		278*/
/*#define	SETRLIMIT_RETURN	279*/
#define	UNDELETE_CALL			280
#define	UNDELETE_RETURN			281
#define	FUTIMES_CALL			282
#define	FUTIMES_RETURN			283
#define	GETPGID_CALL			284
#define	GETPGID_RETURN			285
#define	CLOCK_SETTIME_CALL		286
#define	CLOCK_SETTIME_RETURN		287
/*#define	CLOCK_GETRES_CALL	288*/
/*#define	CLOCK_GETRES_RETURN	289*/
#define	KTIMER_CREATE_CALL		290
#define	KTIMER_CREATE_RETURN		291
#define	KTIMER_DELETE_CALL		292
#define	KTIMER_DELETE_RETURN		293
#define	KTIMER_SETTIME_CALL		294
#define	KTIMER_SETTIME_RETURN		295
#define	KTIMER_GETTIME_CALL		296
#define	KTIMER_GETTIME_RETURN		297
#define	KTIMER_GETOVERRUN_CALL		298
#define	KTIMER_GETOVERRUN_RETURN	299
#define	RFORK_CALL			300
#define	RFORK_RETURN			301
#define	LCHOWN_CALL			302
#define	LCHOWN_RETURN			303
#define	AIO_READ_CALL			304
#define	AIO_READ_RETURN			305
#define	AIO_WRITE_CALL			306
#define	AIO_WRITE_RETURN		307
#define	LIO_LISTIO_CALL			308
#define	LIO_LISTIO_RETURN		309
#define	GETDENTS_CALL			310
#define	GETDENTS_RETURN			311
#define	LCHMOD_CALL			312
#define	LCHMOD_RETURN			313
#define	LUTIMES_CALL			314
#define	LUTIMES_RETURN			315
#define	NSTAT_CALL			316
#define	NSTAT_RETURN			317
#define	NFSTAT_CALL			318
#define	NFSTAT_RETURN			319
#define	NLSTAT_CALL			320
#define	NLSTAT_RETURN			321
#define	PREADV_CALL			322
#define	PREADV_RETURN			323
#define	PWRITEV_CALL			324
#define	PWRITEV_RETURN			325
#define	FHOPEN_CALL			326
#define	FHOPEN_RETURN			327
#define	FHSTAT_CALL			328
#define	FHSTAT_RETURN			329
#define	GETSID_CALL			330
#define	GETSID_RETURN			331
#define	SETRESUID_CALL			332
#define	SETRESUID_RETURN		333
#define	SETRESGID_CALL			334
#define	SETRESGID_RETURN		335
#define	GETRESUID_CALL			336
#define	GETRESUID_RETURN		337
#define	GETRESGID_CALL			338
#define	GETRESGID_RETURN		339
#define	LCHFLAGS_CALL			340
#define	LCHFLAGS_RETURN			341
#define	SENDFILE_CALL			342
#define	SENDFILE_RETURN			343
/*#define	GETFSSTAT_CALL		344*/
/*#define	GETFSSTAT_RETURN	345*/
/*#define	STATFS_CALL		346*/
/*#define	STATFS_RETURN		347*/
#define	FHSTATFS_CALL			348
#define	FHSTATFS_RETURN			349
#define	SETCONTEXT_CALL			350
#define	SETCONTEXT_RETURN		351
#define	SWAPCONTEXT_CALL		352
#define	SWAPCONTEXT_RETURN		353
#define	THR_CREATE_CALL			354
#define	THR_CREATE_RETURN		355
#define	THR_EXIT_CALL			356
#define	THR_EXIT_RETURN			357
/*#define	THR_KILL_CALL		358*/
/*#define	THR_KILL_RETURN		359*/
#define	THR_SUSPEND_CALL		360
#define	THR_SUSPEND_RETURN		361
#define	THR_WAKE_CALL			362
#define	THR_WAKE_RETURN			363
#define	THR_NEW_CALL			364
#define	THR_NEW_RETURN			365
#define	ABORT2_CALL			366
#define	ABORT2_RETURN			367
#define	THR_SET_NAME_CALL		368
#define	THR_SET_NAME_RETURN		369
#define	PWRITE_CALL			370
#define	PWRITE_RETURN			371
#define	TRUNCATE_CALL			372
#define	TRUNCATE_RETURN			373
#define	FTRUNCATE_CALL			374
#define	FTRUNCATE_RETURN		375
#define	THR_KILL2_CALL			376
#define	THR_KILL2_RETURN		377
#define	FACCESSAT_CALL			378
#define	FACCESSAT_RETURN		379
#define	FCHMODAT_CALL			380
#define	FCHMODAT_RETURN			381
#define	FCHOWNAT_CALL			382
#define	FCHOWNAT_RETURN			383
#define	FEXECVE_CALL			384
#define	FEXECVE_RETURN			385
#define	FSTATAT_CALL			386
#define	FSTATAT_RETURN			387
#define	FUTIMESAT_CALL			388
#define	FUTIMESAT_RETURN		389
#define	LINKAT_CALL			390
#define	LINKAT_RETURN			391
#define	MKDIRAT_CALL			392
#define	MKDIRAT_RETURN			393
#define	MKFIFOAT_CALL			394
#define	MKFIFOAT_RETURN			395
#define	MKNODAT_CALL			396
#define	MKNODAT_RETURN			397
#define	OPENAT_CALL			398
#define	OPENAT_RETURN			399
#define	READLINKAT_CALL			400
#define	READLINKAT_RETURN		401
#define	RENAMEAT_CALL			402
#define	RENAMEAT_RETURN			403
#define	SYMLINKAT_CALL			404
#define	SYMLINKAT_RETURN		405
#define	UNLINKAT_CALL			406
#define	UNLINKAT_RETURN			407
#define	POSIX_OPENPT_CALL		408
#define	POSIX_OPENPT_RETURN		409
#define	MSGCTL_CALL			410
#define	MSGCTL_RETURN			411
#define	LPATHCONF_CALL			412
#define	LPATHCONF_RETURN		413
#define	GETLOGINCLASS_CALL		414
#define	GETLOGINCLASS_RETURN		415
#define	SETLOGINCLASS_CALL		416
#define	SETLOGINCLASS_RETURN		417
#define	SIGNALED			418
/*#define	SIGACTION_CALL		420*/
/*#define	SIGACTION_RETURN	421*/
#define	KQUEUE_CALL			422
#define	KQUEUE_RETURN			423
#define	KEVENT_CALL			424
#define	KEVENT_RETURN			425
#define	POLL_START			426
#define	POLL_END			427
#define	POLL_ENDED			428
#define	SIGPROCMASK_CALL		430
#define	SIGPROCMASK_RETURN		431
#define	WAIT6_CALL			432
#define	WAIT6_RETURN			433
#define	BINDAT_CALL			434
#define	BINDAT_RETURN			435
#define	CONNECTAT_CALL			436
#define	CONNECTAT_RETURN		437
#define	CHFLAGSAT_CALL			438
#define	CHFLAGSAT_RETURN		439
#define	ACCEPT4_CALL			440
#define	ACCEPT4_RETURN			441
#define	PIPE2_CALL			442
#define	PIPE2_RETURN			443
#define	PPOLL_CALL			444
#define	PPOLL_RETURN			445
#define	FUTIMENS_CALL			446
#define	FUTIMENS_RETURN			447
#define	UTIMENSAT_CALL			448
#define	UTIMENSAT_RETURN		449

#define	COMPRESSED_WRITEV_CALL		500

/* end command (do not remove this comment) */

/* codes for kevent(2) */
#define	KEVENT_CHANGELIST_NULL		0
#define	KEVENT_CHANGELIST_NOT_NULL	1
#define	KEVENT_TIMEOUT_NULL		0
#define	KEVENT_TIMEOUT_NOT_NULL		1

/* codes for utimes(2) */
#define	UTIMES_TIMES_NULL		0
#define	UTIMES_TIMES_NOT_NULL		1

/* codes for struct kevent */
#define	KEVENT_UDATA_NULL		0
#define	KEVENT_UDATA_NOT_NULL		1

/* codes for struct msghdr */
#define	MSGHDR_MSG_NAME_NULL		0
#define	MSGHDR_MSG_NAME_NOT_NULL	1
#define	MSGHDR_MSG_CONTROL_NULL		0
#define	MSGHDR_MSG_CONTROL_NOT_NULL	1

#endif

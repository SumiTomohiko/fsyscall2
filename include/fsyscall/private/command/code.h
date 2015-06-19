#if !defined(FSYSCALL_PRIVATE_COMMAND_CODE_H_INCLUDED)
#define	FSYSCALL_PRIVATE_COMMAND_CODE_H_INCLUDED

#define	CALL_EXIT		42
#define	RET_EXIT		43
#define	CALL_READ		44
#define	RET_READ		45
#define	CALL_WRITE		46
#define	RET_WRITE		47
#define	CALL_OPEN		48
#define	RET_OPEN		49
#define	CALL_CLOSE		50
#define	RET_CLOSE		51
#define	CALL_LINK		52
#define	RET_LINK		53
#define	CALL_GETPID		54
#define	RET_GETPID		55
#define	CALL_GETUID		56
#define	RET_GETUID		57
#define	CALL_GETEUID		58
#define	RET_GETEUID		59
#define	CALL_ACCESS		60
#define	RET_ACCESS		61
#define	CALL_DUP		62
#define	RET_DUP			63
#define	CALL_GETEGID		64
#define	RET_GETEGID		65
#define	CALL_GETGID		66
#define	RET_GETGID		67
#define	CALL_IOCTL		68
#define	RET_IOCTL		69
#define	CALL_READLINK		70
#define	RET_READLINK		71
#define	CALL_FCNTL		72
#define	RET_FCNTL		73
#define	CALL_SELECT		74
#define	RET_SELECT		75
#define	CALL_WRITEV		76
#define	RET_WRITEV		77
#define	CALL_STAT		78
#define	RET_STAT		79
#define	CALL_FSTAT		80
#define	RET_FSTAT		81
#define	CALL_LSTAT		82
#define	RET_LSTAT		83
#define	CALL_GETDIRENTRIES	84
#define	RET_GETDIRENTRIES	85
#define	CALL_ISSETUGID		86
#define	RET_ISSETUGID		87
#define	CALL_FSTATFS		88
#define	RET_FSTATFS		89
#define	CALL_PREAD		90
#define	RET_PREAD		91
#define	CALL_MMAP		92
#define	RET_MMAP		93
#define	CALL_LSEEK		94
#define	RET_LSEEK		95
#define	CALL_SOCKET		96
#define	RET_SOCKET		97
#define	CALL_CONNECT		98
#define	RET_CONNECT		99
#define	CALL_POLL		100
#define	RET_POLL		101
#define	CALL_RECVFROM		102
#define	RET_RECVFROM		103
#define	CALL_PIPE		104
#define	RET_PIPE		105
#define	CALL_FORK		106
#define	RET_FORK		107
#define	CALL_WAIT4		108
#define	RET_WAIT4		109
#define	CALL_UNLINK		110
#define	RET_UNLINK		111
#define	CALL_CHDIR		112
#define	RET_CHDIR		113
#define	CALL_FCHDIR		114
#define	RET_FCHDIR		115
#define	CALL_MKNOD		116
#define	RET_MKNOD		117
#define	CALL_CHMOD		118
#define	RET_CHMOD		119
#define	CALL_CHOWN		120
#define	RET_CHOWN		121
#define	CALL_MOUNT		122
#define	RET_MOUNT		123
#define	CALL_UNMOUNT		124
#define	RET_UNMOUNT		125
#define	CALL_SETUID		126
#define	RET_SETUID		127
#define	CALL_PTRACE		128
#define	RET_PTRACE		129
#define	CALL_RECVMSG		130
#define	RET_RECVMSG		131
#define	CALL_SENDMSG		132
#define	RET_SENDMSG		133
#define	CALL_ACCEPT		134
#define	RET_ACCEPT		135
#define	CALL_GETPEERNAME	136
#define	RET_GETPEERNAME		137
#define	CALL_GETSOCKNAME	138
#define	RET_GETSOCKNAME		139
#define	CALL_CHFLAGS		140
#define	RET_CHFLAGS		141
#define	CALL_FCHFLAGS		142
#define	RET_FCHFLAGS		143
#define	CALL_SYNC		144
#define	RET_SYNC		145
#define	CALL_KILL		146
#define	RET_KILL		147
#define	CALL_GETPPID		148
#define	RET_GETPPID		149
#define	CALL_PROFIL		150
#define	RET_PROFIL		151
#define	CALL_KTRACE		152
#define	RET_KTRACE		153
#define	CALL_GETLOGIN		154
#define	RET_GETLOGIN		155
#define	CALL_SETLOGIN		156
#define	RET_SETLOGIN		157
#define	CALL_ACCT		158
#define	RET_ACCT		159
#define	CALL_REBOOT		160
#define	RET_REBOOT		161
#define	CALL_REVOKE		162
#define	RET_REVOKE		163
#define	CALL_SYMLINK		164
#define	RET_SYMLINK		165
#define	CALL_EXECVE		166
#define	RET_EXECVE		167
#define	CALL_UMASK		168
#define	RET_UMASK		169
#define	CALL_CHROOT		170
#define	RET_CHROOT		171
#define	CALL_MSYNC		172
#define	RET_MSYNC		173
#define	CALL_VFORK		174
#define	RET_VFORK		175
#define	CALL_OVADVISE		176
#define	RET_OVADVISE		177
#define	CALL_GETGROUPS		178
#define	RET_GETGROUPS		179
#define	CALL_SETGROUPS		180
#define	RET_SETGROUPS		181
#define	CALL_GETPGRP		182
#define	RET_GETPGRP		183
#define	CALL_SETPGID		184
#define	RET_SETPGID		185
#define	CALL_SETITIMER		186
#define	RET_SETITIMER		187
#define	CALL_GETITIMER		188
#define	RET_GETITIMER		189
#define	CALL_DUP2		190
#define	RET_DUP2		191
#define	CALL_FSYNC		192
#define	RET_FSYNC		193
#define	CALL_SETPRIORITY	194
#define	RET_SETPRIORITY		195
#define	CALL_GETPRIORITY	196
#define	RET_GETPRIORITY		197
#define	CALL_BIND		198
#define	RET_BIND		199
#define	CALL_SETSOCKOPT		200
#define	RET_SETSOCKOPT		201
#define	CALL_LISTEN		202
#define	RET_LISTEN		203
#define	CALL_GETTIMEOFDAY	204
#define	RET_GETTIMEOFDAY	205
#define	CALL_GETRUSAGE		206
#define	RET_GETRUSAGE		207
#define	CALL_GETSOCKOPT		208
#define	RET_GETSOCKOPT		209
#define	CALL_READV		210
#define	RET_READV		211
#define	CALL_SETTIMEOFDAY	212
#define	RET_SETTIMEOFDAY	213
#define	CALL_FCHMOD		214
#define	RET_FCHMOD		215
#define	CALL_FCHOWN		216
#define	RET_FCHOWN		217
#define	CALL_SETREUID		218
#define	RET_SETREUID		219
#define	CALL_SETREGID		220
#define	RET_SETREGID		221
#define	CALL_RENAME		222
#define	RET_RENAME		223
#define	CALL_FLOCK		224
#define	RET_FLOCK		225
#define	CALL_MKFIFO		226
#define	RET_MKFIFO		227
#define	CALL_SENDTO		228
#define	RET_SENDTO		229
#define	CALL_SHUTDOWN		230
#define	RET_SHUTDOWN		231
#define	CALL_SOCKETPAIR		232
#define	RET_SOCKETPAIR		233
#define	CALL_MKDIR		234
#define	RET_MKDIR		235
#define	CALL_RMDIR		236
#define	RET_RMDIR		237
#define	CALL_UTIMES		238
#define	RET_UTIMES		239
#define	CALL_ADJTIME		240
#define	RET_ADJTIME		241
/*#define	CALL_SETSID		242*/
/*#define	RET_SETSID		243*/
#define	CALL_QUOTACTL		244
#define	RET_QUOTACTL		245
#define	CALL_NLM_SYSCALL	246
#define	RET_NLM_SYSCALL		247
#define	CALL_NFSSVC		248
#define	RET_NFSSVC		249
#define	CALL_LGETFH		250
#define	RET_LGETFH		251
#define	CALL_GETFH		252
#define	RET_GETFH		253
#define	CALL_RTPRIO		254
#define	RET_RTPRIO		255
#define	CALL_SEMSYS		256
#define	RET_SEMSYS		257
#define	CALL_MSGSYS		258
#define	RET_MSGSYS		259
#define	CALL_SHMSYS		260
#define	RET_SHMSYS		261
#define	CALL_SETFIB		262
#define	RET_SETFIB		263
#define	CALL_NTP_ADJTIME	264
#define	RET_NTP_ADJTIME		265
#define	CALL_SETGID		266
#define	RET_SETGID		267
#define	CALL_SETEGID		268
#define	RET_SETEGID		269
#define	CALL_SETEUID		270
#define	RET_SETEUID		271
#define	CALL_PATHCONF		272
#define	RET_PATHCONF		273
#define	CALL_FPATHCONF		274
#define	RET_FPATHCONF		275
/*#define	CALL_GETRLIMIT		276*/
/*#define	RET_GETRLIMIT		277*/
#define	CALL_SETRLIMIT		278
#define	RET_SETRLIMIT		279
#define	CALL_UNDELETE		280
#define	RET_UNDELETE		281
#define	CALL_FUTIMES		282
#define	RET_FUTIMES		283
#define	CALL_GETPGID		284
#define	RET_GETPGID		285
#define	CALL_CLOCK_SETTIME	286
#define	RET_CLOCK_SETTIME	287
#define	CALL_CLOCK_GETRES	288
#define	RET_CLOCK_GETRES	289
#define	CALL_KTIMER_CREATE	290
#define	RET_KTIMER_CREATE	291
#define	CALL_KTIMER_DELETE	292
#define	RET_KTIMER_DELETE	293
#define	CALL_KTIMER_SETTIME	294
#define	RET_KTIMER_SETTIME	295
#define	CALL_KTIMER_GETTIME	296
#define	RET_KTIMER_GETTIME	297
#define	CALL_KTIMER_GETOVERRUN	298
#define	RET_KTIMER_GETOVERRUN	299
#define	CALL_RFORK		300
#define	RET_RFORK		301
#define	CALL_LCHOWN		302
#define	RET_LCHOWN		303
#define	CALL_AIO_READ		304
#define	RET_AIO_READ		305
#define	CALL_AIO_WRITE		306
#define	RET_AIO_WRITE		307
#define	CALL_LIO_LISTIO		308
#define	RET_LIO_LISTIO		309
#define	CALL_GETDENTS		310
#define	RET_GETDENTS		311
#define	CALL_LCHMOD		312
#define	RET_LCHMOD		313
#define	CALL_LUTIMES		314
#define	RET_LUTIMES		315
#define	CALL_NSTAT		316
#define	RET_NSTAT		317
#define	CALL_NFSTAT		318
#define	RET_NFSTAT		319
#define	CALL_NLSTAT		320
#define	RET_NLSTAT		321
#define	CALL_PREADV		322
#define	RET_PREADV		323
#define	CALL_PWRITEV		324
#define	RET_PWRITEV		325
#define	CALL_FHOPEN		326
#define	RET_FHOPEN		327
#define	CALL_FHSTAT		328
#define	RET_FHSTAT		329
#define	CALL_GETSID		330
#define	RET_GETSID		331
#define	CALL_SETRESUID		332
#define	RET_SETRESUID		333
#define	CALL_SETRESGID		334
#define	RET_SETRESGID		335
#define	CALL_GETRESUID		336
#define	RET_GETRESUID		337
#define	CALL_GETRESGID		338
#define	RET_GETRESGID		339
#define	CALL_LCHFLAGS		340
#define	RET_LCHFLAGS		341
#define	CALL_SENDFILE		342
#define	RET_SENDFILE		343
/*#define	CALL_GETFSSTAT		344*/
/*#define	RET_GETFSSTAT		345*/
/*#define	CALL_STATFS		346*/
/*#define	RET_STATFS		347*/
#define	CALL_FHSTATFS		348
#define	RET_FHSTATFS		349
#define	CALL_SETCONTEXT		350
#define	RET_SETCONTEXT		351
#define	CALL_SWAPCONTEXT	352
#define	RET_SWAPCONTEXT		353
#define	CALL_THR_CREATE		354
#define	RET_THR_CREATE		355
#define	CALL_THR_EXIT		356
#define	RET_THR_EXIT		357
/*#define	CALL_THR_KILL		358*/
/*#define	RET_THR_KILL		359*/
#define	CALL_THR_SUSPEND	360
#define	RET_THR_SUSPEND		361
#define	CALL_THR_WAKE		362
#define	RET_THR_WAKE		363
#define	CALL_THR_NEW		364
#define	RET_THR_NEW		365
#define	CALL_ABORT2		366
#define	RET_ABORT2		367
#define	CALL_THR_SET_NAME	368
#define	RET_THR_SET_NAME	369
#define	CALL_PWRITE		370
#define	RET_PWRITE		371
#define	CALL_TRUNCATE		372
#define	RET_TRUNCATE		373
#define	CALL_FTRUNCATE		374
#define	RET_FTRUNCATE		375
#define	CALL_THR_KILL2		376
#define	RET_THR_KILL2		377
#define	CALL_FACCESSAT		378
#define	RET_FACCESSAT		379
#define	CALL_FCHMODAT		380
#define	RET_FCHMODAT		381
#define	CALL_FCHOWNAT		382
#define	RET_FCHOWNAT		383
#define	CALL_FEXECVE		384
#define	RET_FEXECVE		385
#define	CALL_FSTATAT		386
#define	RET_FSTATAT		387
#define	CALL_FUTIMESAT		388
#define	RET_FUTIMESAT		389
#define	CALL_LINKAT		390
#define	RET_LINKAT		391
#define	CALL_MKDIRAT		392
#define	RET_MKDIRAT		393
#define	CALL_MKFIFOAT		394
#define	RET_MKFIFOAT		395
#define	CALL_MKNODAT		396
#define	RET_MKNODAT		397
#define	CALL_OPENAT		398
#define	RET_OPENAT		399
#define	CALL_READLINKAT		400
#define	RET_READLINKAT		401
#define	CALL_RENAMEAT		402
#define	RET_RENAMEAT		403
#define	CALL_SYMLINKAT		404
#define	RET_SYMLINKAT		405
#define	CALL_UNLINKAT		406
#define	RET_UNLINKAT		407
#define	CALL_POSIX_OPENPT	408
#define	RET_POSIX_OPENPT	409
#define	CALL_MSGCTL		410
#define	RET_MSGCTL		411
#define	CALL_LPATHCONF		412
#define	RET_LPATHCONF		413
#define	CALL_GETLOGINCLASS	414
#define	RET_GETLOGINCLASS	415
#define	CALL_SETLOGINCLASS	416
#define	RET_SETLOGINCLASS	417
#define	SIGNALED		418
#define	CALL_SIGACTION		420
#define	RET_SIGACTION		421
#define	CALL_KQUEUE		422
#define	RET_KQUEUE		423
#define	CALL_KEVENT		424
#define	RET_KEVENT		425

/* end command (do not remove this comment) */

#define	SIGNAL_DEFAULT		0
#define	SIGNAL_IGNORE		1
#define	SIGNAL_ACTIVE		2

#define	KEVENT_CHANGELIST_NULL		0
#define	KEVENT_CHANGELIST_NOT_NULL	1
#define	KEVENT_TIMEOUT_NULL		0
#define	KEVENT_TIMEOUT_NOT_NULL		1
#define	KEVENT_UDATA_NULL		0
#define	KEVENT_UDATA_NOT_NULL		1

#endif

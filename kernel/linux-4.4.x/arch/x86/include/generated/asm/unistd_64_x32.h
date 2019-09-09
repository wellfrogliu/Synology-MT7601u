#ifndef _ASM_X86_UNISTD_64_X32_H
#define _ASM_X86_UNISTD_64_X32_H 1

#define __NR_x32_rt_sigaction 512
#define __NR_x32_rt_sigreturn 513
#define __NR_x32_ioctl 514
#define __NR_x32_readv 515
#define __NR_x32_writev 516
#define __NR_x32_recvfrom 517
#define __NR_x32_sendmsg 518
#define __NR_x32_recvmsg 519
#define __NR_x32_execve 520
#define __NR_x32_ptrace 521
#define __NR_x32_rt_sigpending 522
#define __NR_x32_rt_sigtimedwait 523
#define __NR_x32_rt_sigqueueinfo 524
#define __NR_x32_sigaltstack 525
#define __NR_x32_timer_create 526
#define __NR_x32_mq_notify 527
#define __NR_x32_kexec_load 528
#define __NR_x32_waitid 529
#define __NR_x32_set_robust_list 530
#define __NR_x32_get_robust_list 531
#define __NR_x32_vmsplice 532
#define __NR_x32_move_pages 533
#define __NR_x32_preadv 534
#define __NR_x32_pwritev 535
#define __NR_x32_rt_tgsigqueueinfo 536
#define __NR_x32_recvmmsg 537
#define __NR_x32_sendmmsg 538
#define __NR_x32_process_vm_readv 539
#define __NR_x32_process_vm_writev 540
#define __NR_x32_setsockopt 541
#define __NR_x32_getsockopt 542
#define __NR_x32_io_setup 543
#define __NR_x32_io_submit 544
#define __NR_x32_execveat 545

#ifndef __KERNEL__
#include <bits/wordsize.h>

#define SYNOUtime(arg1, arg2)				syscall(__NR_SYNOUtime, arg1, arg2)

#define SYNOArchiveBit(arg1, arg2)			syscall(__NR_SYNOArchiveBit, arg1, arg2)

#define recvfile(arg1, arg2, arg3, arg4, arg5)		syscall(__NR_recvfile, arg1, arg2, arg3, arg4, arg5)

#define SYNOMTDAlloc(arg1)				syscall(__NR_SYNOMTDAlloc, arg1)

#define SYNOCaselessStat(arg1, arg2)			syscall(__NR_SYNOCaselessStat, arg1, arg2)
#define SYNOCaselessLStat(arg1, arg2)			syscall(__NR_SYNOCaselessLStat, arg1, arg2)

#define SYNOEcryptName(arg1, arg2)			syscall(__NR_SYNOEcryptName, arg1, arg2)
#define SYNODecryptName(arg1, arg2, arg3)		syscall(__NR_SYNODecryptName, arg1, arg2, arg3)

#define SYNOACLSysCheckPerm(arg1, arg2)			syscall(__NR_SYNOACLCheckPerm, arg1, arg2)
#define SYNOACLSysIsSupport(arg1, arg2, arg3)		syscall(__NR_SYNOACLIsSupport, arg1, arg2, arg3)
#define SYNOACLSysGetPerm(arg1, arg2)			syscall(__NR_SYNOACLGetPerm, arg1, arg2)

#define SYNOFlushAggregate(arg1)			syscall(__NR_SYNOFlushAggregate, arg1)

#if (__WORDSIZE == 64) || (_FILE_OFFSET_BITS == 64)
#define SYNOStat(arg1, arg2, arg3)				syscall(__NR_SYNOStat, arg1, arg2, arg3)
#define SYNOFStat(arg1, arg2, arg3)				syscall(__NR_SYNOFStat, arg1, arg2, arg3)
#define SYNOLStat(arg1, arg2, arg3)				syscall(__NR_SYNOLStat, arg1, arg2, arg3)
#endif /* (__WORDSIZE == 64) || (_FILE_OFFSET_BITS == 64) */

#define SYNONotifyInit(arg1)				syscall(__NR_SYNONotifyInit, arg1)
#define SYNONotifyAddWatch(arg1, arg2, arg3)		syscall(__NR_SYNONotifyAddWatch, arg1, arg2, arg3)
#define SYNONotifyRemoveWatch(arg1, arg2, arg3)		syscall(__NR_SYNONotifyRemoveWatch, arg1, arg2, arg3)
#define SYNONotifyAddWatch32(arg1, arg2, arg3)		syscall(__NR_SYNONotifyAddWatch32, arg1, arg2, arg3)
#define SYNONotifyRemoveWatch32(arg1, arg2, arg3)	syscall(__NR_SYNONotifyRemoveWatch32, arg1, arg2, arg3)

#define SYNOArchiveOverwrite(arg1, arg2)		syscall(__NR_SYNOArchiveOverwrite, arg1, arg2)
#endif


#endif /* _ASM_X86_UNISTD_64_X32_H */

#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef _ASM_X86_SYS_IA32_H
#define _ASM_X86_SYS_IA32_H

#ifdef CONFIG_COMPAT

#include <linux/compiler.h>
#include <linux/linkage.h>
#include <linux/types.h>
#include <linux/signal.h>
#include <asm/compat.h>
#include <asm/ia32.h>

asmlinkage long sys32_truncate64(const char __user *, unsigned long, unsigned long);
asmlinkage long sys32_ftruncate64(unsigned int, unsigned long, unsigned long);

asmlinkage long sys32_stat64(const char __user *, struct stat64 __user *);
asmlinkage long sys32_lstat64(const char __user *, struct stat64 __user *);
asmlinkage long sys32_fstat64(unsigned int, struct stat64 __user *);
asmlinkage long sys32_fstatat(unsigned int, const char __user *,
			      struct stat64 __user *, int);
struct mmap_arg_struct32;
asmlinkage long sys32_mmap(struct mmap_arg_struct32 __user *);

asmlinkage long sys32_waitpid(compat_pid_t, unsigned int __user *, int);

asmlinkage long sys32_pread(unsigned int, char __user *, u32, u32, u32);
asmlinkage long sys32_pwrite(unsigned int, const char __user *, u32, u32, u32);

long sys32_fadvise64_64(int, __u32, __u32, __u32, __u32, int);
long sys32_vm86_warning(void);

asmlinkage ssize_t sys32_readahead(int, unsigned, unsigned, size_t);
asmlinkage long sys32_sync_file_range(int, unsigned, unsigned,
				      unsigned, unsigned, int);
asmlinkage long sys32_fadvise64(int, unsigned, unsigned, size_t, int);
asmlinkage long sys32_fallocate(int, int, unsigned,
				unsigned, unsigned, unsigned);

asmlinkage long sys32_sigreturn(void);
asmlinkage long sys32_rt_sigreturn(void);

#ifdef MY_ABC_HERE
#ifdef MY_ABC_HERE
asmlinkage long sys32_SYNOStat64(char __user *, unsigned int, struct SYNOSTAT64 __user *);
asmlinkage long sys32_SYNOFStat64(unsigned int fd, unsigned int flags, struct SYNOSTAT64 __user *);
asmlinkage long sys32_SYNOLStat64(char __user *, unsigned int flags, struct SYNOSTAT64 __user *);
#endif  
#ifdef MY_ABC_HERE
asmlinkage long sys32_SYNOCaselessStat64(char __user *, struct stat64 __user *);
asmlinkage long sys32_SYNOCaselessLStat64(char __user *, struct stat64 __user *);
#endif  
#endif  

#endif  

#endif  

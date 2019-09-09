#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/capability.h>
#include <linux/dnotify.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/pipe_fs_i.h>
#include <linux/security.h>
#include <linux/ptrace.h>
#include <linux/signal.h>
#include <linux/rcupdate.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/shmem_fs.h>

#include <asm/poll.h>
#include <asm/siginfo.h>
#include <asm/uaccess.h>

#ifdef MY_ABC_HERE

#include <linux/mount.h>
#ifdef MY_ABC_HERE
#include "synoacl_int.h"
#define ACL_MASK_NONE 0
#endif  

struct syno_archive_map {
	unsigned int syno_archive;	 
	int is_set_cmd;
};

static struct syno_archive_map syno_archive_table[] = {
	{S2_IARCHIVE, 0},                
	{S2_SMB_ARCHIVE, 1},             
	{S2_SMB_HIDDEN, 1},              
	{S2_SMB_SYSTEM, 1},              
	{S2_SMB_ARCHIVE, 0},             
	{S2_SMB_HIDDEN, 0},              
	{S2_SMB_SYSTEM, 0},              
	{S3_IARCHIVE, 0},                
#ifdef MY_ABC_HERE
	{S2_SMB_READONLY, 0},            
	{S2_SMB_READONLY, 1},            
	{S2_SYNO_ACL_INHERIT, 0},        
	{S2_SYNO_ACL_INHERIT, 1},        
	{S2_SYNO_ACL_EXIST, 0},          
	{S2_SYNO_ACL_EXIST, 1},          
	{S2_SYNO_ACL_SUPPORT, 0},        
	{S2_SYNO_ACL_SUPPORT, 1},        
	{S2_SYNO_ACL_IS_OWNER_GROUP, 0}, 
	{S2_SYNO_ACL_IS_OWNER_GROUP, 1}, 
#endif  
	{S2_SMB_SPARSE, 1},				 
	{S2_SMB_SPARSE, 0},				 
};

#ifdef MY_ABC_HERE
const int syno_archive_acl_tag[] = {
	PROTECT_BY_ACL,                  
	PROTECT_BY_ACL,                  
	PROTECT_BY_ACL,                  
	PROTECT_BY_ACL,                  
	PROTECT_BY_ACL,                  
	PROTECT_BY_ACL,                  
	PROTECT_BY_ACL,                  
	PROTECT_BY_ACL,                  
	PROTECT_BY_ACL | NEED_INODE_ACL_SUPPORT | NEED_FS_ACL_SUPPORT,  
	PROTECT_BY_ACL | NEED_INODE_ACL_SUPPORT | NEED_FS_ACL_SUPPORT,  
	PROTECT_BY_ACL | NEED_INODE_ACL_SUPPORT | NEED_FS_ACL_SUPPORT,  
	PROTECT_BY_ACL | NEED_FS_ACL_SUPPORT,                           
	NEED_INODE_ACL_SUPPORT | NEED_FS_ACL_SUPPORT,                   
	NEED_INODE_ACL_SUPPORT | NEED_FS_ACL_SUPPORT,                   
	NEED_FS_ACL_SUPPORT,                                            
	NEED_FS_ACL_SUPPORT,                                            
	PROTECT_BY_ACL | NEED_INODE_ACL_SUPPORT | NEED_FS_ACL_SUPPORT,  
	PROTECT_BY_ACL | NEED_INODE_ACL_SUPPORT | NEED_FS_ACL_SUPPORT,  
	PROTECT_BY_ACL,                  
	PROTECT_BY_ACL,                  
};

const int syno_archive_acl_mask[] = {
	MAY_WRITE_ATTR,        
	MAY_WRITE_ATTR,        
	MAY_WRITE_ATTR,        
	MAY_WRITE_ATTR,        
	MAY_WRITE_ATTR,        
	MAY_WRITE_ATTR,        
	MAY_WRITE_ATTR,        
	MAY_WRITE_ATTR,        
	MAY_WRITE_ATTR,        
	MAY_WRITE_ATTR,        
	MAY_WRITE_PERMISSION,  
	MAY_WRITE_PERMISSION,  
	ACL_MASK_NONE,         
	ACL_MASK_NONE,         
	ACL_MASK_NONE,         
	ACL_MASK_NONE,         
	MAY_GET_OWNER_SHIP,    
	MAY_GET_OWNER_SHIP,    
	MAY_WRITE_ATTR,        
	MAY_WRITE_ATTR,        
};

struct syno_archive_permission_mapping {
	unsigned int syno_archive;	 
	int permission;
};
static struct syno_archive_permission_mapping syno_archive_permission_table[] = {
	 
	{S2_IARCHIVE, MAY_WRITE_ATTR},
	{S2_SMB_ARCHIVE, MAY_WRITE_ATTR},
	{S2_SMB_HIDDEN, MAY_WRITE_ATTR},
	{S2_SMB_SYSTEM, MAY_WRITE_ATTR},
	{S2_SMB_SPARSE, MAY_WRITE_ATTR},

	{S2_SMB_READONLY, MAY_WRITE_ATTR},
	{S2_SYNO_ACL_IS_OWNER_GROUP, MAY_GET_OWNER_SHIP},
	{S2_SYNO_ACL_INHERIT, MAY_WRITE_PERMISSION},
	{S2_SYNO_ACL_EXIST, MAY_WRITE_PERMISSION},
	{S2_SYNO_ACL_SUPPORT, MAY_WRITE_PERMISSION},
	{0, -1}
};
#endif  

long __SYNOArchiveSet(struct dentry *dentry, unsigned int cmd)
{
	int i = cmd - SYNO_FCNTL_BASE;
	struct inode *inode = dentry->d_inode;
	long err;
	u32 archive_bit;

	mutex_lock(&inode->i_syno_mutex);
	err = syno_op_get_archive_bit(dentry, &archive_bit);
	if (err)
		goto unlock;

	if ((syno_archive_table[i].is_set_cmd ==
		!!(archive_bit & syno_archive_table[i].syno_archive))) {
		err = 0;
		goto unlock;
	}
#ifdef MY_ABC_HERE
	if (0 > (err = synoacl_op_arbit_chg_ok(dentry, cmd, syno_archive_acl_tag[i], syno_archive_acl_mask[i]))) {
		goto unlock;
	}
#endif  
	if (syno_archive_table[i].is_set_cmd) {
		archive_bit |= syno_archive_table[i].syno_archive;
#ifdef MY_ABC_HERE
		if (S2_SYNO_ACL_INHERIT == syno_archive_table[i].syno_archive) {
			archive_bit |= S2_SYNO_ACL_SUPPORT;
		}
#endif  
	} else {
		archive_bit &= ~syno_archive_table[i].syno_archive;
	}

	err = syno_op_set_archive_bit_nolock(dentry, archive_bit);
unlock:
	mutex_unlock(&inode->i_syno_mutex);
	return err;
}
EXPORT_SYMBOL(__SYNOArchiveSet);

long __SYNOArchiveOverwrite(struct dentry *dentry, unsigned int flags)
{
	struct inode *inode = dentry->d_inode;
	int err = 0;
	u32 archive_bit;
#ifdef MY_ABC_HERE
	int permissionCheck = 0;
	int i = 0;
#endif  
	mutex_lock(&inode->i_syno_mutex);
	err = syno_op_get_archive_bit(dentry, &archive_bit);
	if (err)
		goto unlock;

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(dentry)) {
		for (i = 0; -1 != syno_archive_permission_table[i].permission; i++) {
			if ((archive_bit & syno_archive_permission_table[i].syno_archive) == (flags & syno_archive_permission_table[i].syno_archive)) {
				continue;
			}
			permissionCheck |= syno_archive_permission_table[i].permission;
		}
		err = synoacl_op_perm(dentry, permissionCheck);
		if (err) {
			goto unlock;
		}
	} else if (inode->i_op->syno_bypass_is_synoacl) {
		err = inode->i_op->syno_bypass_is_synoacl(dentry,
				       BYPASS_SYNOACL_SYNOARCHIVE_OVERWRITE, -EPERM);
		if (err) {
			goto unlock;
		}
	} else {
		if (!inode_owner_or_capable(inode)) {
			err = -EPERM;
			goto unlock;
		}
	}
	if (ALL_SYNO_ACL_ARCHIVE & flags) {
		if (inode->i_op->syno_bypass_is_synoacl) {
			err = inode->i_op->syno_bypass_is_synoacl(dentry,
					        BYPASS_SYNOACL_SYNOARCHIVE_OVERWRITE_ACL, -EOPNOTSUPP);
			if (err) {
				goto unlock;
			}
		} else if (!IS_FS_SYNOACL(inode)) {
			err = -EOPNOTSUPP;
			goto unlock;
		}
		 
		if (!(S2_SYNO_ACL_SUPPORT & flags)) {
			err = -EINVAL;
			goto unlock;
		}
	}
#else
	if (!inode_owner_or_capable(inode)) {
		err = -EPERM;
		goto unlock;
	}
#endif  
	if ((~ALL_ARCHIVE_BIT) & flags) {
		err = -EINVAL;
		goto unlock;
	}

	if (flags == archive_bit)
		goto unlock;

	err = syno_op_set_archive_bit_nolock(dentry, flags);
unlock:
	mutex_unlock(&inode->i_syno_mutex);
	return err;
}
EXPORT_SYMBOL(__SYNOArchiveOverwrite);
#endif  

#define SETFL_MASK (O_APPEND | O_NONBLOCK | O_NDELAY | O_DIRECT | O_NOATIME)

#ifdef CONFIG_AUFS_FHSM
int setfl(int fd, struct file * filp, unsigned long arg)
#else
static int setfl(int fd, struct file * filp, unsigned long arg)
#endif  
{
	struct inode * inode = file_inode(filp);
	int error = 0;

	if (((arg ^ filp->f_flags) & O_APPEND) && IS_APPEND(inode))
		return -EPERM;

	if ((arg & O_NOATIME) && !(filp->f_flags & O_NOATIME))
		if (!inode_owner_or_capable(inode))
			return -EPERM;

	if (O_NONBLOCK != O_NDELAY)
	       if (arg & O_NDELAY)
		   arg |= O_NONBLOCK;

	if (arg & O_DIRECT) {
		if (!filp->f_mapping || !filp->f_mapping->a_ops ||
			!filp->f_mapping->a_ops->direct_IO)
				return -EINVAL;
	}

	if (filp->f_op->check_flags)
		error = filp->f_op->check_flags(arg);
#ifdef CONFIG_AUFS_FHSM
	if (!error && filp->f_op->setfl)
		error = filp->f_op->setfl(filp, arg);
#endif  
	if (error)
		return error;

	if (((arg ^ filp->f_flags) & FASYNC) && filp->f_op->fasync) {
		error = filp->f_op->fasync(fd, filp, (arg & FASYNC) != 0);
		if (error < 0)
			goto out;
		if (error > 0)
			error = 0;
	}
	spin_lock(&filp->f_lock);
	filp->f_flags = (arg & SETFL_MASK) | (filp->f_flags & ~SETFL_MASK);
	spin_unlock(&filp->f_lock);

 out:
	return error;
}
#ifdef CONFIG_AUFS_FHSM
EXPORT_SYMBOL_GPL(setfl);
#endif  

static void f_modown(struct file *filp, struct pid *pid, enum pid_type type,
                     int force)
{
	write_lock_irq(&filp->f_owner.lock);
	if (force || !filp->f_owner.pid) {
		put_pid(filp->f_owner.pid);
		filp->f_owner.pid = get_pid(pid);
		filp->f_owner.pid_type = type;

		if (pid) {
			const struct cred *cred = current_cred();
			filp->f_owner.uid = cred->uid;
			filp->f_owner.euid = cred->euid;
		}
	}
	write_unlock_irq(&filp->f_owner.lock);
}

void __f_setown(struct file *filp, struct pid *pid, enum pid_type type,
		int force)
{
	security_file_set_fowner(filp);
	f_modown(filp, pid, type, force);
}
EXPORT_SYMBOL(__f_setown);

void f_setown(struct file *filp, unsigned long arg, int force)
{
	enum pid_type type;
	struct pid *pid;
	int who = arg;
	type = PIDTYPE_PID;
	if (who < 0) {
		type = PIDTYPE_PGID;
		who = -who;
	}
	rcu_read_lock();
	pid = find_vpid(who);
	__f_setown(filp, pid, type, force);
	rcu_read_unlock();
}
EXPORT_SYMBOL(f_setown);

void f_delown(struct file *filp)
{
	f_modown(filp, NULL, PIDTYPE_PID, 1);
}

pid_t f_getown(struct file *filp)
{
	pid_t pid;
	read_lock(&filp->f_owner.lock);
	pid = pid_vnr(filp->f_owner.pid);
	if (filp->f_owner.pid_type == PIDTYPE_PGID)
		pid = -pid;
	read_unlock(&filp->f_owner.lock);
	return pid;
}

static int f_setown_ex(struct file *filp, unsigned long arg)
{
	struct f_owner_ex __user *owner_p = (void __user *)arg;
	struct f_owner_ex owner;
	struct pid *pid;
	int type;
	int ret;

	ret = copy_from_user(&owner, owner_p, sizeof(owner));
	if (ret)
		return -EFAULT;

	switch (owner.type) {
	case F_OWNER_TID:
		type = PIDTYPE_MAX;
		break;

	case F_OWNER_PID:
		type = PIDTYPE_PID;
		break;

	case F_OWNER_PGRP:
		type = PIDTYPE_PGID;
		break;

	default:
		return -EINVAL;
	}

	rcu_read_lock();
	pid = find_vpid(owner.pid);
	if (owner.pid && !pid)
		ret = -ESRCH;
	else
		 __f_setown(filp, pid, type, 1);
	rcu_read_unlock();

	return ret;
}

static int f_getown_ex(struct file *filp, unsigned long arg)
{
	struct f_owner_ex __user *owner_p = (void __user *)arg;
	struct f_owner_ex owner;
	int ret = 0;

	read_lock(&filp->f_owner.lock);
	owner.pid = pid_vnr(filp->f_owner.pid);
	switch (filp->f_owner.pid_type) {
	case PIDTYPE_MAX:
		owner.type = F_OWNER_TID;
		break;

	case PIDTYPE_PID:
		owner.type = F_OWNER_PID;
		break;

	case PIDTYPE_PGID:
		owner.type = F_OWNER_PGRP;
		break;

	default:
		WARN_ON(1);
		ret = -EINVAL;
		break;
	}
	read_unlock(&filp->f_owner.lock);

	if (!ret) {
		ret = copy_to_user(owner_p, &owner, sizeof(owner));
		if (ret)
			ret = -EFAULT;
	}
	return ret;
}

#ifdef CONFIG_CHECKPOINT_RESTORE
static int f_getowner_uids(struct file *filp, unsigned long arg)
{
	struct user_namespace *user_ns = current_user_ns();
	uid_t __user *dst = (void __user *)arg;
	uid_t src[2];
	int err;

	read_lock(&filp->f_owner.lock);
	src[0] = from_kuid(user_ns, filp->f_owner.uid);
	src[1] = from_kuid(user_ns, filp->f_owner.euid);
	read_unlock(&filp->f_owner.lock);

	err  = put_user(src[0], &dst[0]);
	err |= put_user(src[1], &dst[1]);

	return err;
}
#else
static int f_getowner_uids(struct file *filp, unsigned long arg)
{
	return -EINVAL;
}
#endif

static long do_fcntl(int fd, unsigned int cmd, unsigned long arg,
		struct file *filp)
{
	long err = -EINVAL;

	switch (cmd) {
	case F_DUPFD:
		err = f_dupfd(arg, filp, 0);
		break;
	case F_DUPFD_CLOEXEC:
		err = f_dupfd(arg, filp, O_CLOEXEC);
		break;
	case F_GETFD:
		err = get_close_on_exec(fd) ? FD_CLOEXEC : 0;
		break;
	case F_SETFD:
		err = 0;
		set_close_on_exec(fd, arg & FD_CLOEXEC);
		break;
	case F_GETFL:
		err = filp->f_flags;
		break;
	case F_SETFL:
		err = setfl(fd, filp, arg);
		break;
#if BITS_PER_LONG != 32
	 
	case F_OFD_GETLK:
#endif
	case F_GETLK:
		err = fcntl_getlk(filp, cmd, (struct flock __user *) arg);
		break;
#if BITS_PER_LONG != 32
	 
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
#endif
		 
	case F_SETLK:
	case F_SETLKW:
		err = fcntl_setlk(fd, filp, cmd, (struct flock __user *) arg);
		break;
	case F_GETOWN:
		 
		err = f_getown(filp);
		force_successful_syscall_return();
		break;
	case F_SETOWN:
		f_setown(filp, arg, 1);
		err = 0;
		break;
	case F_GETOWN_EX:
		err = f_getown_ex(filp, arg);
		break;
	case F_SETOWN_EX:
		err = f_setown_ex(filp, arg);
		break;
	case F_GETOWNER_UIDS:
		err = f_getowner_uids(filp, arg);
		break;
	case F_GETSIG:
		err = filp->f_owner.signum;
		break;
	case F_SETSIG:
		 
		if (!valid_signal(arg)) {
			break;
		}
		err = 0;
		filp->f_owner.signum = arg;
		break;
	case F_GETLEASE:
		err = fcntl_getlease(filp);
		break;
	case F_SETLEASE:
		err = fcntl_setlease(fd, filp, arg);
		break;
	case F_NOTIFY:
		err = fcntl_dirnotify(fd, filp, arg);
		break;
	case F_SETPIPE_SZ:
	case F_GETPIPE_SZ:
		err = pipe_fcntl(filp, cmd, arg);
		break;
	case F_ADD_SEALS:
	case F_GET_SEALS:
		err = shmem_fcntl(filp, cmd, arg);
		break;
#ifdef MY_ABC_HERE
	case SYNO_FCNTL_BASE ... SYNO_FCNTL_LAST:
		err = mnt_want_write(filp->f_path.mnt);
		if (err)
			break;
		err = __SYNOArchiveSet(filp->f_path.dentry, cmd);
		mnt_drop_write(filp->f_path.mnt);
		break;
#endif  
	default:
		break;
	}
	return err;
}

static int check_fcntl_cmd(unsigned cmd)
{
	switch (cmd) {
	case F_DUPFD:
	case F_DUPFD_CLOEXEC:
	case F_GETFD:
	case F_SETFD:
	case F_GETFL:
		return 1;
	}
	return 0;
}

SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
{	
	struct fd f = fdget_raw(fd);
	long err = -EBADF;

	if (!f.file)
		goto out;

	if (unlikely(f.file->f_mode & FMODE_PATH)) {
		if (!check_fcntl_cmd(cmd))
			goto out1;
	}

	err = security_file_fcntl(f.file, cmd, arg);
	if (!err)
		err = do_fcntl(fd, cmd, arg, f.file);

out1:
 	fdput(f);
out:
	return err;
}

#if BITS_PER_LONG == 32
SYSCALL_DEFINE3(fcntl64, unsigned int, fd, unsigned int, cmd,
		unsigned long, arg)
{	
	struct fd f = fdget_raw(fd);
	long err = -EBADF;

	if (!f.file)
		goto out;

	if (unlikely(f.file->f_mode & FMODE_PATH)) {
		if (!check_fcntl_cmd(cmd))
			goto out1;
	}

	err = security_file_fcntl(f.file, cmd, arg);
	if (err)
		goto out1;
	
	switch (cmd) {
	case F_GETLK64:
	case F_OFD_GETLK:
		err = fcntl_getlk64(f.file, cmd, (struct flock64 __user *) arg);
		break;
	case F_SETLK64:
	case F_SETLKW64:
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
		err = fcntl_setlk64(fd, f.file, cmd,
				(struct flock64 __user *) arg);
		break;
	default:
		err = do_fcntl(fd, cmd, arg, f.file);
		break;
	}
out1:
	fdput(f);
out:
	return err;
}
#endif

static const long band_table[NSIGPOLL] = {
	POLLIN | POLLRDNORM,			 
	POLLOUT | POLLWRNORM | POLLWRBAND,	 
	POLLIN | POLLRDNORM | POLLMSG,		 
	POLLERR,				 
	POLLPRI | POLLRDBAND,			 
	POLLHUP | POLLERR			 
};

static inline int sigio_perm(struct task_struct *p,
                             struct fown_struct *fown, int sig)
{
	const struct cred *cred;
	int ret;

	rcu_read_lock();
	cred = __task_cred(p);
	ret = ((uid_eq(fown->euid, GLOBAL_ROOT_UID) ||
		uid_eq(fown->euid, cred->suid) || uid_eq(fown->euid, cred->uid) ||
		uid_eq(fown->uid,  cred->suid) || uid_eq(fown->uid,  cred->uid)) &&
	       !security_file_send_sigiotask(p, fown, sig));
	rcu_read_unlock();
	return ret;
}

static void send_sigio_to_task(struct task_struct *p,
			       struct fown_struct *fown,
			       int fd, int reason, int group)
{
	 
	int signum = ACCESS_ONCE(fown->signum);

	if (!sigio_perm(p, fown, signum))
		return;

	switch (signum) {
		siginfo_t si;
		default:
			 
			si.si_signo = signum;
			si.si_errno = 0;
		        si.si_code  = reason;
			 
			BUG_ON((reason & __SI_MASK) != __SI_POLL);
			if (reason - POLL_IN >= NSIGPOLL)
				si.si_band  = ~0L;
			else
				si.si_band = band_table[reason - POLL_IN];
			si.si_fd    = fd;
			if (!do_send_sig_info(signum, &si, p, group))
				break;
		 
		case 0:
			do_send_sig_info(SIGIO, SEND_SIG_PRIV, p, group);
	}
}

void send_sigio(struct fown_struct *fown, int fd, int band)
{
	struct task_struct *p;
	enum pid_type type;
	struct pid *pid;
	int group = 1;
	
	read_lock(&fown->lock);

	type = fown->pid_type;
	if (type == PIDTYPE_MAX) {
		group = 0;
		type = PIDTYPE_PID;
	}

	pid = fown->pid;
	if (!pid)
		goto out_unlock_fown;
	
	read_lock(&tasklist_lock);
	do_each_pid_task(pid, type, p) {
		send_sigio_to_task(p, fown, fd, band, group);
	} while_each_pid_task(pid, type, p);
	read_unlock(&tasklist_lock);
 out_unlock_fown:
	read_unlock(&fown->lock);
}

static void send_sigurg_to_task(struct task_struct *p,
				struct fown_struct *fown, int group)
{
	if (sigio_perm(p, fown, SIGURG))
		do_send_sig_info(SIGURG, SEND_SIG_PRIV, p, group);
}

int send_sigurg(struct fown_struct *fown)
{
	struct task_struct *p;
	enum pid_type type;
	struct pid *pid;
	int group = 1;
	int ret = 0;
	
	read_lock(&fown->lock);

	type = fown->pid_type;
	if (type == PIDTYPE_MAX) {
		group = 0;
		type = PIDTYPE_PID;
	}

	pid = fown->pid;
	if (!pid)
		goto out_unlock_fown;

	ret = 1;
	
	read_lock(&tasklist_lock);
	do_each_pid_task(pid, type, p) {
		send_sigurg_to_task(p, fown, group);
	} while_each_pid_task(pid, type, p);
	read_unlock(&tasklist_lock);
 out_unlock_fown:
	read_unlock(&fown->lock);
	return ret;
}

static DEFINE_SPINLOCK(fasync_lock);
static struct kmem_cache *fasync_cache __read_mostly;

static void fasync_free_rcu(struct rcu_head *head)
{
	kmem_cache_free(fasync_cache,
			container_of(head, struct fasync_struct, fa_rcu));
}

int fasync_remove_entry(struct file *filp, struct fasync_struct **fapp)
{
	struct fasync_struct *fa, **fp;
	int result = 0;

	spin_lock(&filp->f_lock);
	spin_lock(&fasync_lock);
	for (fp = fapp; (fa = *fp) != NULL; fp = &fa->fa_next) {
		if (fa->fa_file != filp)
			continue;

		spin_lock_irq(&fa->fa_lock);
		fa->fa_file = NULL;
		spin_unlock_irq(&fa->fa_lock);

		*fp = fa->fa_next;
		call_rcu(&fa->fa_rcu, fasync_free_rcu);
		filp->f_flags &= ~FASYNC;
		result = 1;
		break;
	}
	spin_unlock(&fasync_lock);
	spin_unlock(&filp->f_lock);
	return result;
}

struct fasync_struct *fasync_alloc(void)
{
	return kmem_cache_alloc(fasync_cache, GFP_KERNEL);
}

void fasync_free(struct fasync_struct *new)
{
	kmem_cache_free(fasync_cache, new);
}

struct fasync_struct *fasync_insert_entry(int fd, struct file *filp, struct fasync_struct **fapp, struct fasync_struct *new)
{
        struct fasync_struct *fa, **fp;

	spin_lock(&filp->f_lock);
	spin_lock(&fasync_lock);
	for (fp = fapp; (fa = *fp) != NULL; fp = &fa->fa_next) {
		if (fa->fa_file != filp)
			continue;

		spin_lock_irq(&fa->fa_lock);
		fa->fa_fd = fd;
		spin_unlock_irq(&fa->fa_lock);
		goto out;
	}

	spin_lock_init(&new->fa_lock);
	new->magic = FASYNC_MAGIC;
	new->fa_file = filp;
	new->fa_fd = fd;
	new->fa_next = *fapp;
	rcu_assign_pointer(*fapp, new);
	filp->f_flags |= FASYNC;

out:
	spin_unlock(&fasync_lock);
	spin_unlock(&filp->f_lock);
	return fa;
}

static int fasync_add_entry(int fd, struct file *filp, struct fasync_struct **fapp)
{
	struct fasync_struct *new;

	new = fasync_alloc();
	if (!new)
		return -ENOMEM;

	if (fasync_insert_entry(fd, filp, fapp, new)) {
		fasync_free(new);
		return 0;
	}

	return 1;
}

int fasync_helper(int fd, struct file * filp, int on, struct fasync_struct **fapp)
{
	if (!on)
		return fasync_remove_entry(filp, fapp);
	return fasync_add_entry(fd, filp, fapp);
}

EXPORT_SYMBOL(fasync_helper);

static void kill_fasync_rcu(struct fasync_struct *fa, int sig, int band)
{
	while (fa) {
		struct fown_struct *fown;
		unsigned long flags;

		if (fa->magic != FASYNC_MAGIC) {
			printk(KERN_ERR "kill_fasync: bad magic number in "
			       "fasync_struct!\n");
			return;
		}
		spin_lock_irqsave(&fa->fa_lock, flags);
		if (fa->fa_file) {
			fown = &fa->fa_file->f_owner;
			 
			if (!(sig == SIGURG && fown->signum == 0))
				send_sigio(fown, fa->fa_fd, band);
		}
		spin_unlock_irqrestore(&fa->fa_lock, flags);
		fa = rcu_dereference(fa->fa_next);
	}
}

void kill_fasync(struct fasync_struct **fp, int sig, int band)
{
	 
	if (*fp) {
		rcu_read_lock();
		kill_fasync_rcu(rcu_dereference(*fp), sig, band);
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(kill_fasync);

static int __init fcntl_init(void)
{
	 
	BUILD_BUG_ON(21 - 1   != HWEIGHT32(
		O_RDONLY	| O_WRONLY	| O_RDWR	|
		O_CREAT		| O_EXCL	| O_NOCTTY	|
		O_TRUNC		| O_APPEND	|  
		__O_SYNC	| O_DSYNC	| FASYNC	|
		O_DIRECT	| O_LARGEFILE	| O_DIRECTORY	|
		O_NOFOLLOW	| O_NOATIME	| O_CLOEXEC	|
		__FMODE_EXEC	| O_PATH	| __O_TMPFILE	|
		__FMODE_NONOTIFY
		));

	fasync_cache = kmem_cache_create("fasync_cache",
		sizeof(struct fasync_struct), 0, SLAB_PANIC, NULL);
	return 0;
}

module_init(fcntl_init)

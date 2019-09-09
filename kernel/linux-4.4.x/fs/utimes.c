#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
#include <linux/compiler.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/linkage.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <linux/utime.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

#ifdef MY_ABC_HERE
#include "synoacl_int.h"
#endif  
#ifdef __ARCH_WANT_SYS_UTIME

SYSCALL_DEFINE2(utime, char __user *, filename, struct utimbuf __user *, times)
{
	struct timespec tv[2];

	if (times) {
		if (get_user(tv[0].tv_sec, &times->actime) ||
		    get_user(tv[1].tv_sec, &times->modtime))
			return -EFAULT;
		tv[0].tv_nsec = 0;
		tv[1].tv_nsec = 0;
	}
	return do_utimes(AT_FDCWD, filename, times ? tv : NULL, 0);
}

#endif

static bool nsec_valid(long nsec)
{
	if (nsec == UTIME_OMIT || nsec == UTIME_NOW)
		return true;

	return nsec >= 0 && nsec <= 999999999;
}

static int utimes_common(struct path *path, struct timespec *times)
{
	int error;
	struct iattr newattrs;
	struct inode *inode = path->dentry->d_inode;
	struct inode *delegated_inode = NULL;

	error = mnt_want_write(path->mnt);
	if (error)
		goto out;

	if (times && times[0].tv_nsec == UTIME_NOW &&
		     times[1].tv_nsec == UTIME_NOW)
		times = NULL;

	newattrs.ia_valid = ATTR_CTIME | ATTR_MTIME | ATTR_ATIME;
	if (times) {
		if (times[0].tv_nsec == UTIME_OMIT)
			newattrs.ia_valid &= ~ATTR_ATIME;
		else if (times[0].tv_nsec != UTIME_NOW) {
			newattrs.ia_atime.tv_sec = times[0].tv_sec;
			newattrs.ia_atime.tv_nsec = times[0].tv_nsec;
			newattrs.ia_valid |= ATTR_ATIME_SET;
		}

		if (times[1].tv_nsec == UTIME_OMIT)
			newattrs.ia_valid &= ~ATTR_MTIME;
		else if (times[1].tv_nsec != UTIME_NOW) {
			newattrs.ia_mtime.tv_sec = times[1].tv_sec;
			newattrs.ia_mtime.tv_nsec = times[1].tv_nsec;
			newattrs.ia_valid |= ATTR_MTIME_SET;
		}
		 
		newattrs.ia_valid |= ATTR_TIMES_SET;
	} else {
		newattrs.ia_valid |= ATTR_TOUCH;
	}
retry_deleg:
	inode_lock(inode);
	error = notify_change(path->dentry, &newattrs, &delegated_inode);
	inode_unlock(inode);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}

	mnt_drop_write(path->mnt);
out:
	return error;
}

long do_utimes(int dfd, const char __user *filename, struct timespec *times,
	       int flags)
{
	int error = -EINVAL;

	if (times && (!nsec_valid(times[0].tv_nsec) ||
		      !nsec_valid(times[1].tv_nsec))) {
		goto out;
	}

	if (flags & ~AT_SYMLINK_NOFOLLOW)
		goto out;

	if (filename == NULL && dfd != AT_FDCWD) {
		struct fd f;

		if (flags & AT_SYMLINK_NOFOLLOW)
			goto out;

		f = fdget(dfd);
		error = -EBADF;
		if (!f.file)
			goto out;

		error = utimes_common(&f.file->f_path, times);
		fdput(f);
	} else {
		struct path path;
		int lookup_flags = 0;

		if (!(flags & AT_SYMLINK_NOFOLLOW))
			lookup_flags |= LOOKUP_FOLLOW;
retry:
		error = user_path_at(dfd, filename, lookup_flags, &path);
		if (error)
			goto out;

		error = utimes_common(&path, times);
		path_put(&path);
		if (retry_estale(error, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}

out:
	return error;
}

SYSCALL_DEFINE4(utimensat, int, dfd, const char __user *, filename,
		struct timespec __user *, utimes, int, flags)
{
	struct timespec tstimes[2];

	if (utimes) {
		if (copy_from_user(&tstimes, utimes, sizeof(tstimes)))
			return -EFAULT;

		if (tstimes[0].tv_nsec == UTIME_OMIT &&
		    tstimes[1].tv_nsec == UTIME_OMIT)
			return 0;
	}

	return do_utimes(dfd, filename, utimes ? tstimes : NULL, flags);
}

SYSCALL_DEFINE3(futimesat, int, dfd, const char __user *, filename,
		struct timeval __user *, utimes)
{
	struct timeval times[2];
	struct timespec tstimes[2];

	if (utimes) {
		if (copy_from_user(&times, utimes, sizeof(times)))
			return -EFAULT;

		if (times[0].tv_usec >= 1000000 || times[0].tv_usec < 0 ||
		    times[1].tv_usec >= 1000000 || times[1].tv_usec < 0)
			return -EINVAL;

		tstimes[0].tv_sec = times[0].tv_sec;
		tstimes[0].tv_nsec = 1000 * times[0].tv_usec;
		tstimes[1].tv_sec = times[1].tv_sec;
		tstimes[1].tv_nsec = 1000 * times[1].tv_usec;
	}

	return do_utimes(dfd, filename, utimes ? tstimes : NULL, 0);
}

SYSCALL_DEFINE2(utimes, char __user *, filename,
		struct timeval __user *, utimes)
{
	return sys_futimesat(AT_FDCWD, filename, utimes);
}

#ifdef MY_ABC_HERE
 
SYSCALL_DEFINE2(SYNOUtime, const char __user *, filename, struct timespec __user *, ctime)
{
#ifdef MY_ABC_HERE
	int error;
	struct path path;
	struct inode *inode = NULL;
	struct timespec time;

	if (!ctime) {
		return -EINVAL;
	}
	error = copy_from_user(&time, ctime, sizeof(struct timespec));
	if (error)
		goto out;

	error = user_path_at(AT_FDCWD, filename, LOOKUP_FOLLOW, &path);
	if (error)
		goto out;

	error = mnt_want_write(path.mnt);
	if (error)
		goto dput_and_out;

	inode = path.dentry->d_inode;
	if (!inode_owner_or_capable(inode)) {
#ifdef MY_ABC_HERE
		if (IS_SYNOACL(path.dentry)) {
			error = synoacl_op_perm(path.dentry, MAY_WRITE_ATTR | MAY_WRITE_EXT_ATTR);
			if (error)
				goto drop_write;
		} else if (inode->i_op->syno_bypass_is_synoacl) {
			 
			error = inode->i_op->syno_bypass_is_synoacl(path.dentry,
					                BYPASS_SYNOACL_SYNOUTIME, -EPERM);
			if (error)
				goto drop_write;
		} else {
#endif  
		error = -EPERM;
		goto drop_write;
#ifdef MY_ABC_HERE
		}
#endif  
	}

	error = syno_op_set_crtime(path.dentry, &time);

drop_write:
	mnt_drop_write(path.mnt);
dput_and_out:
	path_put(&path);
out:
	return error;
#else
	return -EOPNOTSUPP;
#endif  
}
#endif  

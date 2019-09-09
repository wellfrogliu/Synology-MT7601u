#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/export.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/capability.h>
#include <linux/fsnotify.h>
#include <linux/fcntl.h>
#include <linux/security.h>
#include <linux/evm.h>
#include <linux/ima.h>

#ifdef MY_ABC_HERE
#include "synoacl_int.h"
#endif  
 
int inode_change_ok(const struct inode *inode, struct iattr *attr)
{
	unsigned int ia_valid = attr->ia_valid;

	if (ia_valid & ATTR_SIZE) {
		int error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;
	}

	if (ia_valid & ATTR_FORCE)
		return 0;

	if ((ia_valid & ATTR_UID) &&
	    (!uid_eq(current_fsuid(), inode->i_uid) ||
	     !uid_eq(attr->ia_uid, inode->i_uid)) &&
	    !capable_wrt_inode_uidgid(inode, CAP_CHOWN))
		return -EPERM;

	if ((ia_valid & ATTR_GID) &&
	    (!uid_eq(current_fsuid(), inode->i_uid) ||
	    (!in_group_p(attr->ia_gid) && !gid_eq(attr->ia_gid, inode->i_gid))) &&
	    !capable_wrt_inode_uidgid(inode, CAP_CHOWN))
		return -EPERM;

	if (ia_valid & ATTR_MODE) {
		if (!inode_owner_or_capable(inode))
			return -EPERM;
		 
		if (!in_group_p((ia_valid & ATTR_GID) ? attr->ia_gid :
				inode->i_gid) &&
		    !capable_wrt_inode_uidgid(inode, CAP_FSETID))
			attr->ia_mode &= ~S_ISGID;
	}

	if (ia_valid & (ATTR_MTIME_SET | ATTR_ATIME_SET | ATTR_TIMES_SET)) {
		if (!inode_owner_or_capable(inode))
			return -EPERM;
	}

	return 0;
}
EXPORT_SYMBOL(inode_change_ok);

int inode_newsize_ok(const struct inode *inode, loff_t offset)
{
	if (inode->i_size < offset) {
		unsigned long limit;

		limit = rlimit(RLIMIT_FSIZE);
		if (limit != RLIM_INFINITY && offset > limit)
			goto out_sig;
		if (offset > inode->i_sb->s_maxbytes)
			goto out_big;
	} else {
		 
		if (IS_SWAPFILE(inode))
			return -ETXTBSY;
	}

	return 0;
out_sig:
	send_sig(SIGXFSZ, current, 0);
out_big:
	return -EFBIG;
}
EXPORT_SYMBOL(inode_newsize_ok);

void setattr_copy(struct inode *inode, const struct iattr *attr)
{
	unsigned int ia_valid = attr->ia_valid;

	if (ia_valid & ATTR_UID)
		inode->i_uid = attr->ia_uid;
	if (ia_valid & ATTR_GID)
		inode->i_gid = attr->ia_gid;
	if (ia_valid & ATTR_ATIME)
		inode->i_atime = timespec_trunc(attr->ia_atime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_MTIME)
		inode->i_mtime = timespec_trunc(attr->ia_mtime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_CTIME)
		inode->i_ctime = timespec_trunc(attr->ia_ctime,
						inode->i_sb->s_time_gran);
	if (ia_valid & ATTR_MODE) {
		umode_t mode = attr->ia_mode;

		if (!in_group_p(inode->i_gid) &&
		    !capable_wrt_inode_uidgid(inode, CAP_FSETID))
			mode &= ~S_ISGID;
		inode->i_mode = mode;
	}
}
EXPORT_SYMBOL(setattr_copy);

int notify_change(struct dentry * dentry, struct iattr * attr, struct inode **delegated_inode)
{
	struct inode *inode = dentry->d_inode;
	umode_t mode = inode->i_mode;
	int error;
	struct timespec now;
	unsigned int ia_valid = attr->ia_valid;
#ifdef MY_ABC_HERE
	int isSYNOACL = 0;
#endif  

	WARN_ON_ONCE(!inode_is_locked(inode));

	if (ia_valid & (ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_TIMES_SET)) {
		if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
			return -EPERM;
	}

	if (ia_valid & ATTR_TOUCH) {
		if (IS_IMMUTABLE(inode))
			return -EPERM;

#ifdef MY_ABC_HERE
		if (IS_SYNOACL(dentry)) {
			error = synoacl_op_perm(dentry, MAY_WRITE_ATTR | MAY_WRITE_EXT_ATTR);
			if (error) {
				return error;
			}
		} else
#endif  
		if (!inode_owner_or_capable(inode)) {
			error = inode_permission(inode, MAY_WRITE);
			if (error)
				return error;
		}
	}

	if ((ia_valid & ATTR_MODE)) {
		umode_t amode = attr->ia_mode;
		 
		if (is_sxid(amode))
			inode->i_flags &= ~S_NOSEC;
	}

	now = current_fs_time(inode->i_sb);

	attr->ia_ctime = now;
	if (!(ia_valid & ATTR_ATIME_SET))
		attr->ia_atime = now;
	if (!(ia_valid & ATTR_MTIME_SET))
		attr->ia_mtime = now;
	if (ia_valid & ATTR_KILL_PRIV) {
		attr->ia_valid &= ~ATTR_KILL_PRIV;
		ia_valid &= ~ATTR_KILL_PRIV;
		error = security_inode_need_killpriv(dentry);
		if (error > 0)
			error = security_inode_killpriv(dentry);
		if (error)
			return error;
	}

	if ((ia_valid & (ATTR_KILL_SUID|ATTR_KILL_SGID)) &&
	    (ia_valid & ATTR_MODE))
		BUG();

	if (ia_valid & ATTR_KILL_SUID) {
		if (mode & S_ISUID) {
			ia_valid = attr->ia_valid |= ATTR_MODE;
			attr->ia_mode = (inode->i_mode & ~S_ISUID);
		}
	}
	if (ia_valid & ATTR_KILL_SGID) {
		if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
			if (!(ia_valid & ATTR_MODE)) {
				ia_valid = attr->ia_valid |= ATTR_MODE;
				attr->ia_mode = inode->i_mode;
			}
			attr->ia_mode &= ~S_ISGID;
		}
	}
	if (!(attr->ia_valid & ~(ATTR_KILL_SUID | ATTR_KILL_SGID)))
		return 0;

	error = security_inode_setattr(dentry, attr);
	if (error)
		return error;
	error = try_break_deleg(inode, delegated_inode);
	if (error)
		return error;

#ifdef MY_ABC_HERE
	isSYNOACL = IS_SYNOACL(dentry);
	if (isSYNOACL) {
		error = synoacl_op_inode_chg_ok(dentry, attr);
		if (error) {
			return error;
		}
	}
#endif  
	if (inode->i_op->setattr)
		error = inode->i_op->setattr(dentry, attr);
	else
		error = simple_setattr(dentry, attr);

	if (!error) {
#ifdef MY_ABC_HERE
		if (isSYNOACL) {
			synoacl_op_setattr_post(dentry, attr);
		}
#endif  
		fsnotify_change(dentry, ia_valid);
		ima_inode_post_setattr(dentry);
		evm_inode_post_setattr(dentry, ia_valid);
	}

	return error;
}
EXPORT_SYMBOL(notify_change);

#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/module.h>
#include <linux/tty.h>
#include <linux/namei.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/rcupdate.h>
#include <linux/audit.h>
#include <linux/falloc.h>
#include <linux/fs_struct.h>
#include <linux/ima.h>
#include <linux/dnotify.h>
#include <linux/compat.h>

#include "internal.h"
#ifdef MY_ABC_HERE
#include "synoacl_int.h"
#endif  

#ifdef MY_ABC_HERE
#include <linux/synolib.h>
#endif  

int do_truncate(struct dentry *dentry, loff_t length, unsigned int time_attrs,
	struct file *filp)
{
	int ret;
	struct iattr newattrs;

	if (length < 0)
		return -EINVAL;

	newattrs.ia_size = length;
	newattrs.ia_valid = ATTR_SIZE | time_attrs;
	if (filp) {
		newattrs.ia_file = filp;
		newattrs.ia_valid |= ATTR_FILE;
	}

	ret = dentry_needs_remove_privs(dentry);
	if (ret < 0)
		return ret;
	if (ret)
		newattrs.ia_valid |= ret | ATTR_FORCE;

	inode_lock(dentry->d_inode);
	 
	ret = notify_change(dentry, &newattrs, NULL);
	inode_unlock(dentry->d_inode);
	return ret;
}
#ifdef CONFIG_AUFS_FHSM
EXPORT_SYMBOL_GPL(do_truncate);
#endif  

long vfs_truncate(struct path *path, loff_t length)
{
	struct inode *inode;
	long error;

	inode = path->dentry->d_inode;

	if (S_ISDIR(inode->i_mode))
		return -EISDIR;
	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	error = mnt_want_write(path->mnt);
	if (error)
		goto out;

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(path->dentry)) {
		error = synoacl_op_perm(path->dentry, MAY_WRITE);
	} else
#endif  
	error = inode_permission(inode, MAY_WRITE);
	if (error)
		goto mnt_drop_write_and_out;

	error = -EPERM;
	if (IS_APPEND(inode))
		goto mnt_drop_write_and_out;

	error = get_write_access(inode);
	if (error)
		goto mnt_drop_write_and_out;

	error = break_lease(inode, O_WRONLY);
	if (error)
		goto put_write_and_out;

	error = locks_verify_truncate(inode, NULL, length);
	if (!error)
		error = security_path_truncate(path);
	if (!error)
		error = do_truncate(path->dentry, length, 0, NULL);

put_write_and_out:
	put_write_access(inode);
mnt_drop_write_and_out:
	mnt_drop_write(path->mnt);
out:
	return error;
}
EXPORT_SYMBOL_GPL(vfs_truncate);

static long do_sys_truncate(const char __user *pathname, loff_t length)
{
	unsigned int lookup_flags = LOOKUP_FOLLOW;
	struct path path;
	int error;

	if (length < 0)	 
		return -EINVAL;

retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (!error) {
		error = vfs_truncate(&path, length);
		path_put(&path);
	}
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
	return error;
}

SYSCALL_DEFINE2(truncate, const char __user *, path, long, length)
{
	return do_sys_truncate(path, length);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(truncate, const char __user *, path, compat_off_t, length)
{
	return do_sys_truncate(path, length);
}
#endif

static long do_sys_ftruncate(unsigned int fd, loff_t length, int small)
{
	struct inode *inode;
	struct dentry *dentry;
	struct fd f;
	int error;

	error = -EINVAL;
	if (length < 0)
		goto out;
	error = -EBADF;
	f = fdget(fd);
	if (!f.file)
		goto out;

	if (f.file->f_flags & O_LARGEFILE)
		small = 0;

	dentry = f.file->f_path.dentry;
	inode = dentry->d_inode;
	error = -EINVAL;
	if (!S_ISREG(inode->i_mode) || !(f.file->f_mode & FMODE_WRITE))
		goto out_putf;

	error = -EINVAL;
	 
	if (small && length > MAX_NON_LFS)
		goto out_putf;

	error = -EPERM;
	if (IS_APPEND(inode))
		goto out_putf;

	sb_start_write(inode->i_sb);
	error = locks_verify_truncate(inode, f.file, length);
	if (!error)
		error = security_path_truncate(&f.file->f_path);
	if (!error)
		error = do_truncate(dentry, length, ATTR_MTIME|ATTR_CTIME, f.file);
	sb_end_write(inode->i_sb);
out_putf:
	fdput(f);
out:
	return error;
}

SYSCALL_DEFINE2(ftruncate, unsigned int, fd, unsigned long, length)
{
	return do_sys_ftruncate(fd, length, 1);
}

#ifdef CONFIG_COMPAT
COMPAT_SYSCALL_DEFINE2(ftruncate, unsigned int, fd, compat_ulong_t, length)
{
	return do_sys_ftruncate(fd, length, 1);
}
#endif

#if BITS_PER_LONG == 32
SYSCALL_DEFINE2(truncate64, const char __user *, path, loff_t, length)
{
	return do_sys_truncate(path, length);
}

SYSCALL_DEFINE2(ftruncate64, unsigned int, fd, loff_t, length)
{
	return do_sys_ftruncate(fd, length, 0);
}
#endif  

int vfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	long ret;

	if (offset < 0 || len <= 0)
		return -EINVAL;

	if (mode & ~FALLOC_FL_SUPPORTED_MASK)
		return -EOPNOTSUPP;

	if ((mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE)) ==
	    (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE))
		return -EOPNOTSUPP;

	if ((mode & FALLOC_FL_PUNCH_HOLE) &&
	    !(mode & FALLOC_FL_KEEP_SIZE))
		return -EOPNOTSUPP;

	if ((mode & FALLOC_FL_COLLAPSE_RANGE) &&
	    (mode & ~FALLOC_FL_COLLAPSE_RANGE))
		return -EINVAL;

	if ((mode & FALLOC_FL_INSERT_RANGE) &&
	    (mode & ~FALLOC_FL_INSERT_RANGE))
		return -EINVAL;

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;

	if ((mode & ~FALLOC_FL_KEEP_SIZE) && IS_APPEND(inode))
		return -EPERM;

	if (IS_IMMUTABLE(inode))
		return -EPERM;

	if (IS_SWAPFILE(inode))
		return -ETXTBSY;

	ret = security_file_permission(file, MAY_WRITE);
	if (ret)
		return ret;

	if (S_ISFIFO(inode->i_mode))
		return -ESPIPE;

	if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
		return -ENODEV;

	if (((offset + len) > inode->i_sb->s_maxbytes) || ((offset + len) < 0))
		return -EFBIG;

	if (!file->f_op->fallocate)
		return -EOPNOTSUPP;

	sb_start_write(inode->i_sb);
	ret = file->f_op->fallocate(file, mode, offset, len);

	if (ret == 0)
		fsnotify_modify(file);

	sb_end_write(inode->i_sb);
	return ret;
}
EXPORT_SYMBOL_GPL(vfs_fallocate);

SYSCALL_DEFINE4(fallocate, int, fd, int, mode, loff_t, offset, loff_t, len)
{
	struct fd f = fdget(fd);
	int error = -EBADF;

	if (f.file) {
		error = vfs_fallocate(f.file, mode, offset, len);
		fdput(f);
	}
	return error;
}

#ifdef MY_ABC_HERE
int do_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
	return vfs_fallocate(file, mode, offset, len);
}
EXPORT_SYMBOL(do_fallocate);
#endif  

SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)
{
	const struct cred *old_cred;
	struct cred *override_cred;
	struct path path;
	struct inode *inode;
	int res;
	unsigned int lookup_flags = LOOKUP_FOLLOW;

	if (mode & ~S_IRWXO)	 
		return -EINVAL;

	override_cred = prepare_creds();
	if (!override_cred)
		return -ENOMEM;

	override_cred->fsuid = override_cred->uid;
	override_cred->fsgid = override_cred->gid;

	if (!issecure(SECURE_NO_SETUID_FIXUP)) {
		 
		kuid_t root_uid = make_kuid(override_cred->user_ns, 0);
		if (!uid_eq(override_cred->uid, root_uid))
			cap_clear(override_cred->cap_effective);
		else
			override_cred->cap_effective =
				override_cred->cap_permitted;
	}

	old_cred = override_creds(override_cred);
retry:
	res = user_path_at(dfd, filename, lookup_flags, &path);
	if (res)
		goto out;

	inode = d_backing_inode(path.dentry);

	if ((mode & MAY_EXEC) && S_ISREG(inode->i_mode)) {
		 
		res = -EACCES;
		if (path_noexec(&path))
			goto out_path_release;
	}

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(path.dentry)) {
		res = synoacl_op_access(path.dentry, mode, 0);
	} else
#endif  
	res = inode_permission(inode, mode | MAY_ACCESS);
	 
	if (res || !(mode & S_IWOTH) || special_file(inode->i_mode))
		goto out_path_release;
	 
	if (__mnt_is_readonly(path.mnt))
		res = -EROFS;

out_path_release:
	path_put(&path);
	if (retry_estale(res, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	revert_creds(old_cred);
	put_cred(override_cred);
	return res;
}

SYSCALL_DEFINE2(access, const char __user *, filename, int, mode)
{
	return sys_faccessat(AT_FDCWD, filename, mode);
}

SYSCALL_DEFINE1(chdir, const char __user *, filename)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
retry:
	error = user_path_at(AT_FDCWD, filename, lookup_flags, &path);
	if (error)
		goto out;

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(path.dentry)) {
		error = synoacl_op_perm(path.dentry, MAY_EXEC);
	} else
#endif  
	error = inode_permission(path.dentry->d_inode, MAY_EXEC | MAY_CHDIR);
	if (error)
		goto dput_and_out;

	set_fs_pwd(current->fs, &path);

dput_and_out:
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	return error;
}

SYSCALL_DEFINE1(fchdir, unsigned int, fd)
{
	struct fd f = fdget_raw(fd);
	struct inode *inode;
	int error = -EBADF;

	error = -EBADF;
	if (!f.file)
		goto out;

	inode = file_inode(f.file);

	error = -ENOTDIR;
	if (!S_ISDIR(inode->i_mode))
		goto out_putf;

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(f.file->f_path.dentry)) {
		error = synoacl_op_perm(f.file->f_path.dentry, MAY_EXEC);
	} else
#endif  
	error = inode_permission(inode, MAY_EXEC | MAY_CHDIR);
	if (!error)
		set_fs_pwd(current->fs, &f.file->f_path);
out_putf:
	fdput(f);
out:
	return error;
}

SYSCALL_DEFINE1(chroot, const char __user *, filename)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_FOLLOW | LOOKUP_DIRECTORY;
retry:
	error = user_path_at(AT_FDCWD, filename, lookup_flags, &path);
	if (error)
		goto out;

#ifdef MY_ABC_HERE
	if (IS_SYNOACL(path.dentry)) {
		error = synoacl_op_perm(path.dentry, MAY_EXEC);
	} else
#endif  
	error = inode_permission(path.dentry->d_inode, MAY_EXEC | MAY_CHDIR);
	if (error)
		goto dput_and_out;

	error = -EPERM;
	if (!ns_capable(current_user_ns(), CAP_SYS_CHROOT))
		goto dput_and_out;
	error = security_path_chroot(&path);
	if (error)
		goto dput_and_out;

	set_fs_root(current->fs, &path);
	error = 0;
dput_and_out:
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	return error;
}

static int chmod_common(struct path *path, umode_t mode)
{
	struct inode *inode = path->dentry->d_inode;
	struct inode *delegated_inode = NULL;
	struct iattr newattrs;
	int error;

	error = mnt_want_write(path->mnt);
	if (error)
		return error;
retry_deleg:
	inode_lock(inode);
	error = security_path_chmod(path, mode);
	if (error)
		goto out_unlock;
	newattrs.ia_mode = (mode & S_IALLUGO) | (inode->i_mode & ~S_IALLUGO);
	newattrs.ia_valid = ATTR_MODE | ATTR_CTIME;
	error = notify_change(path->dentry, &newattrs, &delegated_inode);
out_unlock:
	inode_unlock(inode);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	mnt_drop_write(path->mnt);
	return error;
}

SYSCALL_DEFINE2(fchmod, unsigned int, fd, umode_t, mode)
{
	struct fd f = fdget(fd);
	int err = -EBADF;

	if (f.file) {
		audit_file(f.file);
		err = chmod_common(&f.file->f_path, mode);
		fdput(f);
	}
	return err;
}

SYSCALL_DEFINE3(fchmodat, int, dfd, const char __user *, filename, umode_t, mode)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_FOLLOW;
retry:
	error = user_path_at(dfd, filename, lookup_flags, &path);
	if (!error) {
		error = chmod_common(&path, mode);
		path_put(&path);
		if (retry_estale(error, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}
	return error;
}

SYSCALL_DEFINE2(chmod, const char __user *, filename, umode_t, mode)
{
	return sys_fchmodat(AT_FDCWD, filename, mode);
}

static int chown_common(struct path *path, uid_t user, gid_t group)
{
	struct inode *inode = path->dentry->d_inode;
	struct inode *delegated_inode = NULL;
	int error;
	struct iattr newattrs;
	kuid_t uid;
	kgid_t gid;

	uid = make_kuid(current_user_ns(), user);
	gid = make_kgid(current_user_ns(), group);

retry_deleg:
	newattrs.ia_valid =  ATTR_CTIME;
	if (user != (uid_t) -1) {
		if (!uid_valid(uid))
			return -EINVAL;
		newattrs.ia_valid |= ATTR_UID;
		newattrs.ia_uid = uid;
	}
	if (group != (gid_t) -1) {
		if (!gid_valid(gid))
			return -EINVAL;
		newattrs.ia_valid |= ATTR_GID;
		newattrs.ia_gid = gid;
	}
	if (!S_ISDIR(inode->i_mode))
		newattrs.ia_valid |=
			ATTR_KILL_SUID | ATTR_KILL_SGID | ATTR_KILL_PRIV;
	inode_lock(inode);
	error = security_path_chown(path, uid, gid);
	if (!error)
		error = notify_change(path->dentry, &newattrs, &delegated_inode);
	inode_unlock(inode);
	if (delegated_inode) {
		error = break_deleg_wait(&delegated_inode);
		if (!error)
			goto retry_deleg;
	}
	return error;
}

SYSCALL_DEFINE5(fchownat, int, dfd, const char __user *, filename, uid_t, user,
		gid_t, group, int, flag)
{
	struct path path;
	int error = -EINVAL;
	int lookup_flags;

	if ((flag & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0)
		goto out;

	lookup_flags = (flag & AT_SYMLINK_NOFOLLOW) ? 0 : LOOKUP_FOLLOW;
	if (flag & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;
retry:
	error = user_path_at(dfd, filename, lookup_flags, &path);
	if (error)
		goto out;
	error = mnt_want_write(path.mnt);
	if (error)
		goto out_release;
	error = chown_common(&path, user, group);
	mnt_drop_write(path.mnt);
out_release:
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	return error;
}

SYSCALL_DEFINE3(chown, const char __user *, filename, uid_t, user, gid_t, group)
{
	return sys_fchownat(AT_FDCWD, filename, user, group, 0);
}

SYSCALL_DEFINE3(lchown, const char __user *, filename, uid_t, user, gid_t, group)
{
	return sys_fchownat(AT_FDCWD, filename, user, group,
			    AT_SYMLINK_NOFOLLOW);
}

SYSCALL_DEFINE3(fchown, unsigned int, fd, uid_t, user, gid_t, group)
{
	struct fd f = fdget(fd);
	int error = -EBADF;

	if (!f.file)
		goto out;

	error = mnt_want_write_file(f.file);
	if (error)
		goto out_fput;
	audit_file(f.file);
	error = chown_common(&f.file->f_path, user, group);
	mnt_drop_write_file(f.file);
out_fput:
	fdput(f);
out:
	return error;
}

int open_check_o_direct(struct file *f)
{
	 
	if (f->f_flags & O_DIRECT) {
		if (!f->f_mapping->a_ops || !f->f_mapping->a_ops->direct_IO)
			return -EINVAL;
	}
	return 0;
}
#ifdef CONFIG_AUFS_FHSM
EXPORT_SYMBOL_GPL(open_check_o_direct);
#endif  

static int do_dentry_open(struct file *f,
			  struct inode *inode,
			  int (*open)(struct inode *, struct file *),
			  const struct cred *cred)
{
	static const struct file_operations empty_fops = {};
	int error;

	f->f_mode = OPEN_FMODE(f->f_flags) | FMODE_LSEEK |
				FMODE_PREAD | FMODE_PWRITE;

	path_get(&f->f_path);
	f->f_inode = inode;
	f->f_mapping = inode->i_mapping;
#ifdef MY_ABC_HERE
	file_sb_list_add(f, inode->i_sb);
#endif  

	if (unlikely(f->f_flags & O_PATH)) {
		f->f_mode = FMODE_PATH;
		f->f_op = &empty_fops;
		return 0;
	}

	if (f->f_mode & FMODE_WRITE && !special_file(inode->i_mode)) {
		error = get_write_access(inode);
		if (unlikely(error))
			goto cleanup_file;
		error = __mnt_want_write(f->f_path.mnt);
		if (unlikely(error)) {
			put_write_access(inode);
			goto cleanup_file;
		}
		f->f_mode |= FMODE_WRITER;
	}

	if (S_ISREG(inode->i_mode))
		f->f_mode |= FMODE_ATOMIC_POS;

	f->f_op = fops_get(inode->i_fop);
	if (unlikely(WARN_ON(!f->f_op))) {
		error = -ENODEV;
		goto cleanup_all;
	}

#ifdef MY_ABC_HERE
	if (inode->i_opflags & IOP_ECRYPTFS_LOWER_INIT) {
		inode->i_opflags &= ~IOP_ECRYPTFS_LOWER_INIT;
	} else {
#endif  
	error = security_file_open(f, cred);
	if (error)
		goto cleanup_all;
#ifdef MY_ABC_HERE
	}
#endif  

	error = break_lease(inode, f->f_flags);
	if (error)
		goto cleanup_all;

	if (!open)
		open = f->f_op->open;
	if (open) {
		error = open(inode, f);
		if (error)
			goto cleanup_all;
	}
	if ((f->f_mode & (FMODE_READ | FMODE_WRITE)) == FMODE_READ)
		i_readcount_inc(inode);
	if ((f->f_mode & FMODE_READ) &&
	     likely(f->f_op->read || f->f_op->read_iter))
		f->f_mode |= FMODE_CAN_READ;
	if ((f->f_mode & FMODE_WRITE) &&
	     likely(f->f_op->write || f->f_op->write_iter))
		f->f_mode |= FMODE_CAN_WRITE;

	f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);

	file_ra_state_init(&f->f_ra, f->f_mapping->host->i_mapping);

	return 0;

cleanup_all:
	fops_put(f->f_op);
#ifdef MY_ABC_HERE
	file_sb_list_del(f);
#endif  
	if (f->f_mode & FMODE_WRITER) {
		put_write_access(inode);
		__mnt_drop_write(f->f_path.mnt);
	}
cleanup_file:
	path_put(&f->f_path);
	f->f_path.mnt = NULL;
	f->f_path.dentry = NULL;
	f->f_inode = NULL;
	return error;
}

int finish_open(struct file *file, struct dentry *dentry,
		int (*open)(struct inode *, struct file *),
		int *opened)
{
	int error;
	BUG_ON(*opened & FILE_OPENED);  

	file->f_path.dentry = dentry;
	error = do_dentry_open(file, d_backing_inode(dentry), open,
			       current_cred());
	if (!error)
		*opened |= FILE_OPENED;

	return error;
}
EXPORT_SYMBOL(finish_open);

int finish_no_open(struct file *file, struct dentry *dentry)
{
	file->f_path.dentry = dentry;
	return 1;
}
EXPORT_SYMBOL(finish_no_open);

char *file_path(struct file *filp, char *buf, int buflen)
{
	return d_path(&filp->f_path, buf, buflen);
}
EXPORT_SYMBOL(file_path);

int vfs_open(const struct path *path, struct file *file,
	     const struct cred *cred)
{
	struct inode *inode = vfs_select_inode(path->dentry, file->f_flags);

	if (IS_ERR(inode))
		return PTR_ERR(inode);

	file->f_path = *path;
	return do_dentry_open(file, inode, NULL, cred);
}

struct file *dentry_open(const struct path *path, int flags,
			 const struct cred *cred)
{
	int error;
	struct file *f;

	validate_creds(cred);

	BUG_ON(!path->mnt);

	f = get_empty_filp();
	if (!IS_ERR(f)) {
		f->f_flags = flags;
		error = vfs_open(path, f, cred);
		if (!error) {
			 
			error = open_check_o_direct(f);
			if (error) {
				fput(f);
				f = ERR_PTR(error);
			}
		} else {
			put_filp(f);
			f = ERR_PTR(error);
		}
	}
	return f;
}
EXPORT_SYMBOL(dentry_open);

static inline int build_open_flags(int flags, umode_t mode, struct open_flags *op)
{
	int lookup_flags = 0;
	int acc_mode;

	if (flags & (O_CREAT | __O_TMPFILE))
		op->mode = (mode & S_IALLUGO) | S_IFREG;
	else
		op->mode = 0;

	flags &= ~FMODE_NONOTIFY & ~O_CLOEXEC;

	if (flags & __O_SYNC)
		flags |= O_DSYNC;

	if (flags & __O_TMPFILE) {
		if ((flags & O_TMPFILE_MASK) != O_TMPFILE)
			return -EINVAL;
		acc_mode = MAY_OPEN | ACC_MODE(flags);
		if (!(acc_mode & MAY_WRITE))
			return -EINVAL;
	} else if (flags & O_PATH) {
		 
		flags &= O_DIRECTORY | O_NOFOLLOW | O_PATH;
		acc_mode = 0;
	} else {
		acc_mode = MAY_OPEN | ACC_MODE(flags);
	}

	op->open_flag = flags;

	if (flags & O_TRUNC)
		acc_mode |= MAY_WRITE;

	if (flags & O_APPEND)
		acc_mode |= MAY_APPEND;

	op->acc_mode = acc_mode;

	op->intent = flags & O_PATH ? 0 : LOOKUP_OPEN;

	if (flags & O_CREAT) {
		op->intent |= LOOKUP_CREATE;
		if (flags & O_EXCL)
			op->intent |= LOOKUP_EXCL;
	}

	if (flags & O_DIRECTORY)
		lookup_flags |= LOOKUP_DIRECTORY;
	if (!(flags & O_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	op->lookup_flags = lookup_flags;
	return 0;
}

struct file *file_open_name(struct filename *name, int flags, umode_t mode)
{
	struct open_flags op;
	int err = build_open_flags(flags, mode, &op);
	return err ? ERR_PTR(err) : do_filp_open(AT_FDCWD, name, &op);
}

struct file *filp_open(const char *filename, int flags, umode_t mode)
{
	struct filename *name = getname_kernel(filename);
	struct file *file = ERR_CAST(name);

	if (!IS_ERR(name)) {
		file = file_open_name(name, flags, mode);
		putname(name);
	}
	return file;
}
EXPORT_SYMBOL(filp_open);

struct file *file_open_root(struct dentry *dentry, struct vfsmount *mnt,
			    const char *filename, int flags, umode_t mode)
{
	struct open_flags op;
	int err = build_open_flags(flags, mode, &op);
	if (err)
		return ERR_PTR(err);
	return do_file_open_root(dentry, mnt, filename, &op);
}
EXPORT_SYMBOL(file_open_root);

long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
	struct open_flags op;
	int fd = build_open_flags(flags, mode, &op);
	struct filename *tmp;

	if (fd)
		return fd;

	tmp = getname(filename);
	if (IS_ERR(tmp))
		return PTR_ERR(tmp);

	fd = get_unused_fd_flags(flags);
	if (fd >= 0) {
		struct file *f = do_filp_open(dfd, tmp, &op);
		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			fsnotify_open(f);
			fd_install(fd, f);
		}
	}
	putname(tmp);
	return fd;
}

SYSCALL_DEFINE3(open, const char __user *, filename, int, flags, umode_t, mode)
{
	if (force_o_largefile())
		flags |= O_LARGEFILE;

#ifdef MY_ABC_HERE
	if (0 < gSynoHibernationLogLevel) {
		syno_do_hibernation_filename_log(filename);
	}
#endif  

	return do_sys_open(AT_FDCWD, filename, flags, mode);
}

SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags,
		umode_t, mode)
{
	if (force_o_largefile())
		flags |= O_LARGEFILE;

	return do_sys_open(dfd, filename, flags, mode);
}

#ifndef __alpha__

SYSCALL_DEFINE2(creat, const char __user *, pathname, umode_t, mode)
{
	return sys_open(pathname, O_CREAT | O_WRONLY | O_TRUNC, mode);
}

#endif

int filp_close(struct file *filp, fl_owner_t id)
{
	int retval = 0;

	if (!file_count(filp)) {
		printk(KERN_ERR "VFS: Close: file count is 0\n");
		return 0;
	}

	if (filp->f_op->flush)
		retval = filp->f_op->flush(filp, id);

	if (likely(!(filp->f_mode & FMODE_PATH))) {
		dnotify_flush(filp, id);
		locks_remove_posix(filp, id);
	}
	fput(filp);
	return retval;
}

EXPORT_SYMBOL(filp_close);

SYSCALL_DEFINE1(close, unsigned int, fd)
{
	int retval = __close_fd(current->files, fd);

	if (unlikely(retval == -ERESTARTSYS ||
		     retval == -ERESTARTNOINTR ||
		     retval == -ERESTARTNOHAND ||
		     retval == -ERESTART_RESTARTBLOCK))
		retval = -EINTR;

	return retval;
}
EXPORT_SYMBOL(sys_close);

SYSCALL_DEFINE0(vhangup)
{
	if (capable(CAP_SYS_TTY_CONFIG)) {
		tty_vhangup_self();
		return 0;
	}
	return -EPERM;
}

int generic_file_open(struct inode * inode, struct file * filp)
{
	if (!(filp->f_flags & O_LARGEFILE) && i_size_read(inode) > MAX_NON_LFS)
		return -EOVERFLOW;
	return 0;
}

EXPORT_SYMBOL(generic_file_open);

int nonseekable_open(struct inode *inode, struct file *filp)
{
	filp->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);
	return 0;
}

EXPORT_SYMBOL(nonseekable_open);

#ifdef MY_ABC_HERE
extern long __SYNOArchiveSet(struct dentry *dentry, unsigned int cmd);
extern long __SYNOArchiveOverwrite(struct dentry *dentry, unsigned int flags);
#endif  

#ifdef MY_ABC_HERE
SYSCALL_DEFINE2(SYNOArchiveBit, const char __user *, filename, int, cmd)
{
#ifdef MY_ABC_HERE
	struct path path;
	long error;

	if (SYNO_FCNTL_BASE > cmd || SYNO_FCNTL_LAST < cmd) {
		printk(KERN_WARNING "Archive bit cmd:%x not implement.\n", cmd);
		return -EINVAL;
	}

	error = user_path_at(AT_FDCWD, filename, LOOKUP_FOLLOW, &path);
	if (error)
		return error;

	error = mnt_want_write(path.mnt);
	if (error)
		goto out_release;

	error = __SYNOArchiveSet(path.dentry, cmd);
	mnt_drop_write(path.mnt);
out_release:
	path_put(&path);
	return error;
#else
	return -EOPNOTSUPP;
#endif  
}

SYSCALL_DEFINE2(SYNOArchiveOverwrite, unsigned int, fd, unsigned int, flags)
{
#ifdef MY_ABC_HERE
	struct fd f = fdget(fd);
	int error = -EBADF;

	if (!f.file) {
		return error;
	}

	error = mnt_want_write(f.file->f_path.mnt);
	if (error)
		goto fput_out;

	error = __SYNOArchiveOverwrite(f.file->f_path.dentry, flags);
	mnt_drop_write(f.file->f_path.mnt);
fput_out:
	fdput(f);
	return error;
#else
	return -EOPNOTSUPP;
#endif  
}

#ifdef MY_ABC_HERE
#include "ecryptfs/ecryptfs_kernel.h"
int (*fecryptfs_decode_and_decrypt_filename)(char **plaintext_name,
                                        size_t *plaintext_name_size,
                                        struct super_block *sb,
                                        const char *name, size_t name_size) = NULL;
EXPORT_SYMBOL(fecryptfs_decode_and_decrypt_filename);
#endif  

SYSCALL_DEFINE2(SYNOEcryptName, const char __user *, src, char __user *, dst)
{
#ifdef MY_ABC_HERE
	int                               err = -1;
	struct qstr                      *lower_path = NULL;
	struct path                       path;
	struct ecryptfs_dentry_info      *crypt_dentry = NULL;

	if (NULL == src || NULL == dst) {
		return -EINVAL;
	}

	err = user_path_at(AT_FDCWD, src, LOOKUP_FOLLOW, &path);

	if (err) {
		return -ENOENT;
	}
	if (!path.dentry->d_inode->i_sb->s_type ||
		strcmp(path.dentry->d_inode->i_sb->s_type->name, "ecryptfs")) {
		err = -EINVAL;
		goto OUT_RELEASE;
	}
	crypt_dentry = ecryptfs_dentry_to_private(path.dentry);
	if (!crypt_dentry) {
		err = -EINVAL;
		goto OUT_RELEASE;
	}
	lower_path = &crypt_dentry->lower_path.dentry->d_name;
	err = copy_to_user(dst, lower_path->name, lower_path->len + 1);

OUT_RELEASE:
	path_put(&path);

	return err;
#else
	return -EOPNOTSUPP;
#endif  
}

SYSCALL_DEFINE3(SYNODecryptName, const char __user *, root, const char __user *, src, char __user *, dst)
{
#ifdef MY_ABC_HERE
	int                           err;
	size_t                        plaintext_name_size = 0;
	char                         *plaintext_name = NULL;
	char                         *token = NULL;
	char                         *target = NULL;
	struct filename              *root_name = NULL;
	struct filename              *src_name = NULL;
	char                         *src_walk = NULL;
	char                         *src_orig = NULL;
	struct path					 path;

	if (NULL == src || NULL == root || NULL == dst) {
		return -EINVAL;
	}
	if (!fecryptfs_decode_and_decrypt_filename) {
		return -EPERM;
	}

	root_name = getname(root);
	if (IS_ERR(root_name)) {
		err = PTR_ERR(root_name);
		goto OUT_RELEASE;
	}
	target = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!target) {
		err = -ENOMEM;
		goto OUT_RELEASE;
	}
	strncpy(target, root_name->name, PATH_MAX-1);
	target[PATH_MAX-1] = '\0';

	src_name = getname(src);
	if (IS_ERR(src_name)) {
		err = PTR_ERR(src_name);
		goto OUT_RELEASE;
	}
	 
	src_walk = kstrdup(src_name->name, GFP_KERNEL);
	if (!src_walk) {
		err = -ENOMEM;
		goto OUT_RELEASE;
	}
	src_orig = src_walk;

	token = strsep(&src_walk, "/");

	while (token) {
		if (*token == '\0') {
			strcat(target, "/");
			token = strsep(&src_walk, "/");
			continue;
		}
		err = kern_path(target, LOOKUP_FOLLOW, &path);
		if (err) {
			goto OUT_RELEASE;
		}

		if (!path.dentry->d_inode->i_sb->s_type ||
			strcmp(path.dentry->d_inode->i_sb->s_type->name, "ecryptfs")) {
			strcat(target, "/");
			strcat(target, token);
			token = strsep(&src_walk, "/");
			path_put(&path);
			continue;
		}

		err = fecryptfs_decode_and_decrypt_filename(
			&plaintext_name, &plaintext_name_size, path.dentry->d_sb, token, strlen(token));
		if (err) {
			path_put(&path);
			goto OUT_RELEASE;
		}
		if (PATH_MAX < strlen(target) + plaintext_name_size + 1) {
			path_put(&path);
			goto OUT_RELEASE;
		}
		strcat(target, "/");
		strcat(target, plaintext_name);

		kfree(plaintext_name);
		plaintext_name = NULL;
		path_put(&path);

		token = strsep(&src_walk, "/");
	}
	err = copy_to_user(dst, target, strlen(target)+1);

OUT_RELEASE:
	if (src_orig) {
		kfree(src_orig);
	}
	if (plaintext_name) {
		kfree(plaintext_name);
	}
	if (target) {
		kfree(target);
	}
	if (!IS_ERR(src_name)) {
		putname(src_name);
	}
	if (!IS_ERR(root_name)) {
		putname(root_name);
	}

	return err;

#else
	return -EOPNOTSUPP;
#endif  
}
#endif  

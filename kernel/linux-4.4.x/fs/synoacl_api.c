#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifdef MY_ABC_HERE
#include <linux/syscalls.h>
#endif  
#ifdef MY_ABC_HERE
#include <linux/kernel.h>
#include <linux/slab.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/file.h>

#include "synoacl_int.h"

#define VFS_MODULE	psynoacl_vfs_op
#define SYSCALL_MODULE	psynoacl_syscall_op

#define IS_VFS_ACL_READY(x) (VFS_MODULE && VFS_MODULE->x)
#define IS_SYSCALL_ACL_READY(x) (SYSCALL_MODULE && SYSCALL_MODULE->x)
#define DO_VFS(x, ...) VFS_MODULE->x(__VA_ARGS__)
#define DO_SYSCALL(x, ...) SYSCALL_MODULE->x(__VA_ARGS__)

struct synoacl_vfs_operations *VFS_MODULE = NULL;
struct synoacl_syscall_operations *SYSCALL_MODULE = NULL;

int SYNOACLModuleStatusGet(const char *szModName)
{
	int st = -1;
	struct module *mod = NULL;

	mutex_lock(&module_mutex);

	if (NULL == (mod = find_module(szModName))) {
		goto Err;
	}

	st = mod->state;
Err:
	mutex_unlock(&module_mutex);

	return st;
}
EXPORT_SYMBOL(SYNOACLModuleStatusGet);

void UseACLModule(const char *szModName, int isGet)
{
	struct module *mod = NULL;

	mutex_lock(&module_mutex);

	if (NULL == (mod = find_module(szModName))) {
		printk("synoacl module [%s] is not loaded \n", szModName);
		goto Err;
	}

	if (isGet) {
		try_module_get(mod);
	} else {
		module_put(mod);
	}
Err:
	mutex_unlock(&module_mutex);
}
EXPORT_SYMBOL(UseACLModule);

int synoacl_vfs_register(struct synoacl_vfs_operations *pvfs, struct synoacl_syscall_operations *psys)
{
	if (!pvfs || !psys) {
		return -1;
	}

	VFS_MODULE = pvfs;
	SYSCALL_MODULE = psys;

	return 0;
}
EXPORT_SYMBOL(synoacl_vfs_register);

void synoacl_vfs_unregister(void)
{
	VFS_MODULE = NULL;
	SYSCALL_MODULE = NULL;
}
EXPORT_SYMBOL(synoacl_vfs_unregister);

int synoacl_mod_archive_change_ok(struct dentry *d, unsigned int cmd, int tag, int mask)
{
	if (IS_VFS_ACL_READY(archive_change_ok)) {
		return DO_VFS(archive_change_ok, d, cmd, tag, mask);
	}
	return 0;  
}
EXPORT_SYMBOL(synoacl_mod_archive_change_ok);

int synoacl_mod_may_delete(struct dentry *d, struct inode *dir)
{
	if (IS_VFS_ACL_READY(syno_acl_may_delete)) {
		return DO_VFS(syno_acl_may_delete, d, dir, 1);
	}
	return inode_permission(dir, MAY_WRITE | MAY_EXEC);
}
EXPORT_SYMBOL(synoacl_mod_may_delete);

int synoacl_mod_setattr_post(struct dentry *dentry, struct iattr *attr)
{
	if (IS_VFS_ACL_READY(syno_acl_setattr_post)) {
		return DO_VFS(syno_acl_setattr_post, dentry, attr);
	}
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(synoacl_mod_setattr_post);

int synoacl_mod_inode_change_ok(struct dentry *d, struct iattr *attr)
{
	if (IS_VFS_ACL_READY(syno_inode_change_ok)) {
		return DO_VFS(syno_inode_change_ok, d, attr);
	}
	return inode_change_ok(d->d_inode, attr);
}
EXPORT_SYMBOL(synoacl_mod_inode_change_ok);

void synoacl_mod_to_mode(struct dentry *d, struct kstat *stat)
{
	if (IS_VFS_ACL_READY(syno_acl_to_mode)) {
		DO_VFS(syno_acl_to_mode, d, stat);
	}
}
EXPORT_SYMBOL(synoacl_mod_to_mode);

int synoacl_mod_access(struct dentry *d, int mask, int syno_acl_access)
{
	if (IS_VFS_ACL_READY(syno_acl_access)) {
		return DO_VFS(syno_acl_access, d, mask, syno_acl_access);
	}
	return inode_permission(d->d_inode, mask);
}
EXPORT_SYMBOL(synoacl_mod_access);

int synoacl_mod_exec_permission(struct dentry *d)
{
	if (IS_VFS_ACL_READY(syno_acl_exec_permission)) {
		return DO_VFS(syno_acl_exec_permission, d);
	}
	return 0;
}
EXPORT_SYMBOL(synoacl_mod_exec_permission);

int synoacl_mod_permission(struct dentry *d, int mask)
{
	if (IS_VFS_ACL_READY(syno_acl_permission)) {
		return DO_VFS(syno_acl_permission, d, mask);
	}
	return 0;
}
EXPORT_SYMBOL(synoacl_mod_permission);

int synoacl_mod_get_acl_xattr(struct dentry *d, int cmd, void *value, size_t size)
{
	if (IS_VFS_ACL_READY(syno_acl_xattr_get)) {
		return DO_VFS(syno_acl_xattr_get, d, cmd, value, size);
	}
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(synoacl_mod_get_acl_xattr);

int synoacl_mod_init_acl(struct dentry *dentry, struct inode *inode)
{
	if (IS_VFS_ACL_READY(syno_acl_init)) {
		return DO_VFS(syno_acl_init, dentry, inode);
	}
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(synoacl_mod_init_acl);
#endif  

#ifdef MY_ABC_HERE
SYSCALL_DEFINE2(SYNOACLCheckPerm, const char __user *, name, int , mask)
{
#ifdef MY_ABC_HERE
	int is_path_get = 0;
	struct path path;
	struct inode * inode = NULL;
	int error = -EINVAL;

	error = user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW, &path);
	if (error)
		goto out;

	is_path_get = 1;

	if (path.dentry && path.dentry->d_inode) {
		inode = path.dentry->d_inode;
	} else {
		goto out;
	}

	if (inode->i_op->syno_acl_sys_check_perm) {
		error = inode->i_op->syno_acl_sys_check_perm(path.dentry, mask);
		if (error != -EOPNOTSUPP) {
			goto out;
		}
	}
	if (IS_SYSCALL_ACL_READY(check_perm)) {
		error = DO_SYSCALL(check_perm, path.dentry, mask);
	} else {
		error = -EOPNOTSUPP;
	}

out:
	if (is_path_get) {
		path_put(&path);
	}
	return error;
#else
	return 0;
#endif  
}

SYSCALL_DEFINE3(SYNOACLIsSupport, const char __user *, name, int , fd, int , tag)
{
#ifdef MY_ABC_HERE
	int is_path_get = 0;
	struct path path;
	struct file *fp = NULL;
	struct inode *inode = NULL;
	struct dentry *dentry = NULL;
	int error = -EINVAL;

	if (name) {
		error = user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW, &path);
		if (error)
			goto out;

		is_path_get = 1;

		if (!path.dentry || !path.dentry->d_inode) {
			goto out;
		}
		inode = path.dentry->d_inode;
		dentry = path.dentry;
	} else if (fd >= 0) {
		fp = fget(fd);
		if (!fp || !fp->f_path.dentry){
			error = -EBADF;
			goto out;
		}
		inode = fp->f_path.dentry->d_inode;
		dentry = fp->f_path.dentry;
	} else {
		goto out;
	}

	if (inode->i_op->syno_acl_sys_is_support) {
		error = inode->i_op->syno_acl_sys_is_support(dentry, tag);
		if (error != -EOPNOTSUPP) {
			goto out;
		}
	}
	if (IS_SYSCALL_ACL_READY(is_acl_support)) {
		error = DO_SYSCALL(is_acl_support, dentry, tag);
	} else {
		error = -EOPNOTSUPP;
	}
out:
	if (is_path_get) {
		path_put(&path);
	}
	if (fp) {
		fput(fp);
	}

	return error;
#else
	return 0;
#endif  
}

SYSCALL_DEFINE2(SYNOACLGetPerm, const char __user *, name, int __user *, out_perm)
{
#ifdef MY_ABC_HERE
	int is_path_get = 0;
	unsigned int perm_allow = 0;
	int error = -EINVAL;
	struct path path;
	struct inode * inode = NULL;

	error = user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW, &path);
	if (error)
		goto err;

	is_path_get = 1;

	if (path.dentry && path.dentry->d_inode) {
		inode = path.dentry->d_inode;
	} else {
		goto err;
	}

	if (IS_SYNOACL_SUPERUSER()) {
		perm_allow = SYNO_PERM_FULL_CONTROL;
		error = 0;
		goto end;
	}

	if (inode->i_op->syno_acl_sys_get_perm) {
		error = inode->i_op->syno_acl_sys_get_perm(path.dentry, &perm_allow);
		if (error != -EOPNOTSUPP) {
			goto end;
		}
	}
	if (IS_SYSCALL_ACL_READY(get_perm)) {
		error = DO_SYSCALL(get_perm, path.dentry, &perm_allow);
	} else {
		error = -EOPNOTSUPP;
	}
end:
	if (copy_to_user(out_perm, &perm_allow, sizeof(perm_allow))){
		error = -EFAULT;
		goto err;
	}

err:
	if (is_path_get) {
		path_put(&path);
	}

	return error;
#else
	return 0;
#endif  
}
#endif  

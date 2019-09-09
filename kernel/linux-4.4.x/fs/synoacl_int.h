#ifndef MY_ABC_HERE
#define MY_ABC_HERE
#endif
 
#ifndef __LINUX_SYNOACL_INT_H
#define __LINUX_SYNOACL_INT_H

#ifdef MY_ABC_HERE
#include <linux/syno_acl.h>

#define PROTECT_BY_ACL 0x0001
#define NEED_INODE_ACL_SUPPORT 0x0004
#define NEED_FS_ACL_SUPPORT 0x0008

struct synoacl_syscall_operations {
	int (*get_perm) (struct dentry *dentry, int *allow_out);
	int (*is_acl_support) (struct dentry *dentry, int tag);
	int (*check_perm) (struct dentry *dentry, int mask);
};

struct synoacl_vfs_operations {
	int (*archive_change_ok) (struct dentry *d, unsigned int cmd, int tag, int mask);
	int (*syno_acl_may_delete) (struct dentry *, struct inode *, int);
	int (*syno_acl_setattr_post) (struct dentry *dentry, struct iattr *);
	int (*syno_inode_change_ok) (struct dentry *d, struct iattr *attr);
	int (*syno_acl_access) (struct dentry *d, int mask, int syno_acl_access);
	void (*syno_acl_to_mode) (struct dentry *d, struct kstat *stat);
	int (*syno_acl_exec_permission) (struct dentry *d);
	int (*syno_acl_permission)(struct dentry *d, int mask);
	int (*syno_acl_xattr_get) (struct dentry *d, int cmd, void *value, size_t size);
	int (*syno_acl_init) (struct dentry *d, struct inode *inode);
};

int synoacl_mod_archive_change_ok(struct dentry *, unsigned int , int , int );
int synoacl_mod_may_delete(struct dentry *, struct inode *);
int synoacl_mod_setattr_post(struct dentry *, struct iattr *);
int synoacl_mod_init_acl(struct dentry *, struct inode *);
int synoacl_mod_inode_change_ok(struct dentry *, struct iattr *);
int synoacl_mod_access(struct dentry *, int, int);
void synoacl_mod_to_mode(struct dentry *, struct kstat *);
int synoacl_mod_exec_permission(struct dentry *);
int synoacl_mod_permission(struct dentry *, int);
int synoacl_mod_get_acl_xattr(struct dentry *, int, void *, size_t);

static inline int synoacl_op_perm(struct dentry * dentry, int perm)
{
	struct inode *inode = dentry->d_inode;

	if (inode->i_op->syno_permission) {
		return inode->i_op->syno_permission(dentry, perm);
	}
	 
	return synoacl_mod_permission(dentry, perm);
}

static inline int synoacl_op_exec_perm(struct dentry * dentry, struct inode * inode)
{
	if (inode->i_op->syno_exec_permission) {
		return inode->i_op->syno_exec_permission(dentry);
	}
	 
	return synoacl_mod_exec_permission(dentry);
}

static inline int synoacl_op_access(struct dentry * dentry, int mode, int syno_acl_access)
{
	struct inode *inode = dentry->d_inode;

	if (inode->i_op->syno_acl_access) {
		return inode->i_op->syno_acl_access(dentry, mode, syno_acl_access);
	}
	return synoacl_mod_access(dentry, mode, syno_acl_access);
}

static inline int synoacl_op_may_delete(struct dentry *victim, struct inode *dir)
{
	if (dir->i_op->syno_may_delete) {
		return dir->i_op->syno_may_delete(victim, dir);
	}
	return synoacl_mod_may_delete(victim, dir);
}

static inline void synoacl_op_to_mode(struct dentry *dentry, struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;

	if (inode->i_op->syno_acl_to_mode) {
		inode->i_op->syno_acl_to_mode(dentry, stat);
	} else {
		synoacl_mod_to_mode(dentry, stat);
	}
}

static inline int synoacl_op_xattr_get(struct dentry * dentry, int cmd, void *value, size_t size)
{
	struct inode *inode = dentry->d_inode;

	if (inode->i_op->syno_acl_xattr_get) {
		return inode->i_op->syno_acl_xattr_get(dentry, cmd, value, size);
	}

	return synoacl_mod_get_acl_xattr(dentry, cmd, value, size);
}

static inline int synoacl_op_inode_chg_ok(struct dentry * dentry, struct iattr * attr)
{
	struct inode *inode = dentry->d_inode;

	if (inode->i_op->syno_inode_change_ok) {
		return inode->i_op->syno_inode_change_ok(dentry, attr);
	}

	return synoacl_mod_inode_change_ok(dentry, attr);
}

static inline int synoacl_op_arbit_chg_ok(struct dentry *d, unsigned int cmd, int tag, int mask)
{
	struct inode *inode = d->d_inode;

	if (inode->i_op->syno_arbit_chg_ok) {
		return inode->i_op->syno_arbit_chg_ok(d, cmd, tag, mask);
	}

	return synoacl_mod_archive_change_ok(d, cmd, tag, mask);
}

static inline void synoacl_op_setattr_post(struct dentry * dentry, struct iattr * attr)
{
	struct inode *inode = dentry->d_inode;

	if (inode->i_op->syno_setattr_post) {
		inode->i_op->syno_setattr_post(dentry, attr);
	} else {
		synoacl_mod_setattr_post(dentry, attr);
	}
}

static inline void synoacl_op_init(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	if (inode->i_op->syno_acl_init) {
		inode->i_op->syno_acl_init(dentry, inode);
	} else {
		synoacl_mod_init_acl(dentry, inode);
	}
}

static inline int synoacl_check_xattr_perm(const char *name, struct dentry *dentry, unsigned int perm)
{
	int error = 0;

	if (!name || strcmp(name, SYNO_ACL_XATTR_ACCESS)) {
		return 0;  
	}

	switch (perm) {
	case MAY_READ_PERMISSION:
		if (!IS_SYNOACL(dentry)) {
			 
			return -EOPNOTSUPP;
		}
		break;
	case MAY_WRITE_PERMISSION:
		if (!IS_FS_SYNOACL(dentry->d_inode)) {
			return -EOPNOTSUPP;
		}
		break;
	default:  
		return 0;
	}

	error = synoacl_op_perm(dentry, perm);
	if (error) {
		 
		return error;
	}

	return 0;
}

#endif  
#endif   
